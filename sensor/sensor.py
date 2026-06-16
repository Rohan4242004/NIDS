import sys
import os
import time
import threading
import requests
from scapy.all import sniff, IP, TCP, UDP

# Central API URL for ingestion
API_INGEST_URL = os.getenv("API_INGEST_URL", "http://localhost:8000/api/v1/logs/ingest")
SNIFFER_INTERFACE = os.getenv("SNIFFER_INTERFACE", None)

class DecoupledNetworkSensor:
    def __init__(self, backend_url=API_INGEST_URL):
        self.backend_url = backend_url
        self.is_running = False
        self.active_flows = {}
        self.flow_lock = threading.Lock()
        self.proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        
    def start(self, interface=None):
        if self.is_running:
            print("[Sensor] Sensor is already running.")
            return
            
        self.is_running = True
        print(f"[Sensor] Initialising NIDS external sensor. Target collector: {self.backend_url}")
        
        # 1. Start cleanup worker thread for idle flows
        self.cleanup_thread = threading.Thread(target=self._idle_flows_reaper, daemon=True)
        self.cleanup_thread.start()
        
        # 2. Start sniffer thread
        self.sniffer_thread = threading.Thread(target=self._run_sniffer, args=(interface,), daemon=True)
        self.sniffer_thread.start()
        
        print("[Sensor] Sensor threads spawned. Listening for network packets...")

    def stop(self):
        self.is_running = False
        print("[Sensor] Stopped sensor capturing.")

    def _run_sniffer(self, interface):
        def parse_packet(pkt):
            if not self.is_running:
                return
            if IP in pkt:
                self._process_packet(pkt)
                
        try:
            # prn directs Scapy to process callback, store=0 prevents memory bloating
            sniff(iface=interface, prn=parse_packet, store=0)
        except Exception as e:
            print(f"[Sensor] Sniffer runtime error: {e}", file=sys.stderr)

    def _process_packet(self, pkt):
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        
        # Port & Flags initialization
        src_port = 0
        dst_port = 0
        flags = {"FIN": 0, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 0}
        
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            tcp_flags = pkt[TCP].flags
            if 'F' in tcp_flags: flags["FIN"] = 1
            if 'S' in tcp_flags: flags["SYN"] = 1
            if 'R' in tcp_flags: flags["RST"] = 1
            if 'P' in tcp_flags: flags["PSH"] = 1
            if 'A' in tcp_flags: flags["ACK"] = 1
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        # Bidirectional Key Grouping
        flow_key1 = (src_ip, src_port, dst_ip, dst_port, proto)
        flow_key2 = (dst_ip, dst_port, src_ip, src_port, proto)
        
        pkt_len = len(pkt)
        timestamp = time.time()
        
        with self.flow_lock:
            if flow_key1 in self.active_flows:
                self._update_flow(self.active_flows[flow_key1], pkt_len, flags, timestamp, "fwd")
            elif flow_key2 in self.active_flows:
                self._update_flow(self.active_flows[flow_key2], pkt_len, flags, timestamp, "bwd")
            else:
                self.active_flows[flow_key1] = {
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": proto,
                    "start_time": timestamp,
                    "last_active": timestamp,
                    "tot_fw_pkts": 1,
                    "tot_bw_pkts": 0,
                    "tot_l_fw_pkts": pkt_len,
                    "tot_l_bw_pkts": 0,
                    "flags_fin": flags["FIN"],
                    "flags_syn": flags["SYN"],
                    "flags_rst": flags["RST"],
                    "flags_psh": flags["PSH"],
                    "flags_ack": flags["ACK"]
                }
                
        # Flush connection flows immediately if RST or FIN flags are parsed
        if flags["FIN"] == 1 or flags["RST"] == 1:
            self._flush_flow(flow_key1 if flow_key1 in self.active_flows else flow_key2)

    def _update_flow(self, flow, pkt_len, flags, timestamp, direction):
        flow["last_active"] = timestamp
        if direction == "fwd":
            flow["tot_fw_pkts"] += 1
            flow["tot_l_fw_pkts"] += pkt_len
        else:
            flow["tot_bw_pkts"] += 1
            flow["tot_l_bw_pkts"] += pkt_len
            
        flow["flags_fin"] |= flags["FIN"]
        flow["flags_syn"] |= flags["SYN"]
        flow["flags_rst"] |= flags["RST"]
        flow["flags_psh"] |= flags["PSH"]
        flow["flags_ack"] |= flags["ACK"]

    def _idle_flows_reaper(self):
        while self.is_running:
            time.sleep(2)
            now = time.time()
            expired_keys = []
            
            with self.flow_lock:
                for key, flow in self.active_flows.items():
                    # Flush flow if idle for more than 5.0 seconds
                    if now - flow["last_active"] > 5.0:
                        expired_keys.append(key)
                        
            for key in expired_keys:
                self._flush_flow(key)

    def _flush_flow(self, key):
        with self.flow_lock:
            flow = self.active_flows.pop(key, None)
            
        if flow:
            duration = max(0.001, flow["last_active"] - flow["start_time"])
            tot_fw = flow["tot_fw_pkts"]
            tot_bw = flow["tot_bw_pkts"]
            tot_l_fw = flow["tot_l_fw_pkts"]
            tot_l_bw = flow["tot_l_bw_pkts"]
            
            flow_bytes_s = (tot_l_fw + tot_l_bw) / duration
            flow_pkts_s = (tot_fw + tot_bw) / duration
            
            proto = flow["protocol"]
            fwd_header_len = tot_fw * (20 + (20 if proto == 6 else 8))
            bwd_header_len = tot_bw * (20 + (20 if proto == 6 else 8))
            
            # Map into the 15 features required by central ML Classifier models
            feature_vector = [
                duration, tot_fw, tot_bw, tot_l_fw, tot_l_bw,
                flow_bytes_s, flow_pkts_s, fwd_header_len, bwd_header_len,
                flow["flags_fin"], flow["flags_syn"], flow["flags_rst"], 
                flow["flags_psh"], flow["flags_ack"], proto
            ]
            
            payload = {
                "src_ip": flow["src_ip"],
                "src_port": flow["src_port"],
                "dst_ip": flow["dst_ip"],
                "dst_port": flow["dst_port"],
                "protocol": self.proto_map.get(proto, "OTHER"),
                "duration": duration,
                "total_packets": tot_fw + tot_bw,
                "total_bytes": tot_l_fw + tot_l_bw,
                "features": feature_vector
            }
            
            # Stream JSON payload to the central API collector asynchronously
            threading.Thread(target=self._send_payload, args=(payload,), daemon=True).start()

    def _send_payload(self, payload):
        try:
            res = requests.post(self.backend_url, json=payload, timeout=5)
            if res.status_code == 201:
                result = res.json()
                print(f"[Sensor] Ingested flow. Prediction: {result['prediction']} ({result['confidence']:.1%}) - Alert: {result['alert_triggered']}")
            else:
                print(f"[Sensor] Ingestion HTTP error {res.status_code}: {res.text}", file=sys.stderr)
        except Exception as e:
            print(f"[Sensor] Network error transmitting payload: {e}", file=sys.stderr)

if __name__ == "__main__":
    sensor = DecoupledNetworkSensor()
    
    # Check command-line interface arguments for specific sniffer cards
    interface = sys.argv[1] if len(sys.argv) > 1 else SNIFFER_INTERFACE
    
    sensor.start(interface=interface)
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[Sensor] Stopping sensor capture...")
        sensor.stop()
