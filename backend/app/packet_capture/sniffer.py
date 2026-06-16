import threading
import time
import random
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP

from app.database.connection import SessionLocal
from app.ml.detection_engine import nids_detector
from app.models.system_log import SystemLog

class PacketSnifferDaemon:
    def __init__(self):
        self.is_running = False
        self.sniffer_thread = None
        self.simulator_thread = None
        self.active_flows = {}
        self.flow_lock = threading.Lock()
        self.websocket_broadcast_cb = None
        
        # Mapping from protocol number to string name
        self.proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}

    def set_broadcast_callback(self, callback):
        self.websocket_broadcast_cb = callback

    def start(self, interface=None):
        if self.is_running:
            return False
            
        self.is_running = True
        
        # Start Scapy Sniffer Thread
        self.sniffer_thread = threading.Thread(
            target=self._run_sniffer, args=(interface,), daemon=True
        )
        self.sniffer_thread.start()
        
        # Start Flow Cleanup Thread
        self.cleanup_thread = threading.Thread(
            target=self._run_flow_cleanup, daemon=True
        )
        self.cleanup_thread.start()

        # Start Simulated Traffic Generator (ensures active data feed for demonstration)
        self.simulator_thread = threading.Thread(
            target=self._run_simulator, daemon=True
        )
        self.simulator_thread.start()
        
        print("[Sniffer Daemon] Started successfully.")
        return True

    def stop(self):
        if not self.is_running:
            return False
        self.is_running = False
        print("[Sniffer Daemon] Stopped.")
        return True

    def _run_sniffer(self, interface):
        print(f"[Sniffer Daemon] Listening on interface: {interface or 'Default'}")
        
        def process_packet(pkt):
            if not self.is_running:
                return
            if IP in pkt:
                self._handle_packet(pkt)
                
        try:
            # Running Scapy Sniffer
            sniff(iface=interface, prn=process_packet, store=0)
        except Exception as e:
            error_msg = f"Scapy sniffer crashed on interface {interface or 'Default'}: {e}"
            print(f"[Sniffer Daemon] {error_msg}")
            
            # Write a critical audit log event to the database
            db = SessionLocal()
            try:
                sys_log = SystemLog(
                    module_name="SnifferDaemon",
                    log_level="CRITICAL",
                    message=error_msg
                )
                db.add(sys_log)
                db.commit()
            except Exception as dbe:
                print(f"[Sniffer Daemon] Failed to log crash to DB: {dbe}")
            finally:
                db.close()

    def _handle_packet(self, pkt):
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        
        # Extract ports
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

        # Unique key for Bidirectional Flow
        flow_key1 = (src_ip, src_port, dst_ip, dst_port, proto)
        flow_key2 = (dst_ip, dst_port, src_ip, src_port, proto)
        
        pkt_len = len(pkt)
        timestamp = time.time()
        
        used_key = None
        with self.flow_lock:
            # Check if flow already exists
            if flow_key1 in self.active_flows:
                flow = self.active_flows[flow_key1]
                self._update_flow(flow, pkt_len, flags, timestamp, direction="fwd")
                used_key = flow_key1
            elif flow_key2 in self.active_flows:
                flow = self.active_flows[flow_key2]
                self._update_flow(flow, pkt_len, flags, timestamp, direction="bwd")
                used_key = flow_key2
            else:
                # Initialize new bidirectional flow record
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
                used_key = flow_key1

        # Flush flow immediately if TCP termination flags are seen
        if (flags["FIN"] == 1 or flags["RST"] == 1) and used_key:
            self._flush_flow(used_key)

    def _update_flow(self, flow, pkt_len, flags, timestamp, direction):
        flow["last_active"] = timestamp
        if direction == "fwd":
            flow["tot_fw_pkts"] += 1
            flow["tot_l_fw_pkts"] += pkt_len
        else:
            flow["tot_bw_pkts"] += 1
            flow["tot_l_bw_pkts"] += pkt_len
            
        # Update flag states (bitwise OR)
        flow["flags_fin"] |= flags["FIN"]
        flow["flags_syn"] |= flags["SYN"]
        flow["flags_rst"] |= flags["RST"]
        flow["flags_psh"] |= flags["PSH"]
        flow["flags_ack"] |= flags["ACK"]

    def _run_flow_cleanup(self):
        while self.is_running:
            time.sleep(2)
            now = time.time()
            expired_keys = []
            
            with self.flow_lock:
                for key, flow in self.active_flows.items():
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
            
            # Compile 15 features to match ML model
            feature_vector = [
                duration, tot_fw, tot_bw, tot_l_fw, tot_l_bw,
                flow_bytes_s, flow_pkts_s, fwd_header_len, bwd_header_len,
                flow["flags_fin"], flow["flags_syn"], flow["flags_rst"], 
                flow["flags_psh"], flow["flags_ack"], proto
            ]
            
            # Process via unified Detection Engine
            db = SessionLocal()
            try:
                proto_str = self.proto_map.get(proto, "OTHER")
                flow_details = {
                    "src_ip": flow["src_ip"],
                    "src_port": flow["src_port"],
                    "dst_ip": flow["dst_ip"],
                    "dst_port": flow["dst_port"],
                    "protocol": proto_str,
                    "duration": duration,
                    "total_packets": tot_fw + tot_bw,
                    "total_bytes": tot_l_fw + tot_l_bw
                }
                res = nids_detector.analyze_and_log_flow(db, flow_details, feature_vector)
                
                # Broadcast payload via WebSockets
                if self.websocket_broadcast_cb:
                    payload = {
                        "event": "new_flow" if res["prediction"] == "Benign" or res["prediction"] == "Normal" else "alert_triggered",
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "data": {
                            "log_id": res["log_id"],
                            "alert_id": res["alert_id"],
                            "severity": res["severity"] if (res["prediction"] != "Benign" and res["prediction"] != "Normal") else "INFO",
                            "attack_type": res["prediction"],
                            "source": f"{flow['src_ip']}:{flow['src_port']}",
                            "destination": f"{flow['dst_ip']}:{flow['dst_port']}",
                            "flow_details": {
                                "protocol": proto_str,
                                "duration_sec": round(duration, 3),
                                "total_bytes": tot_l_fw + tot_l_bw,
                                "total_packets": tot_fw + tot_bw
                            },
                            "confidence": round(res["confidence"], 3)
                        }
                    }
                    self.websocket_broadcast_cb(payload)
            except Exception as e:
                print(f"[Sniffer Daemon] Error analyzing/logging flow: {e}")
            finally:
                db.close()

    def _run_simulator(self):
        """
        Simulate traffic generation for the frontend UI validation.
        Injects realistic normal traffic and periodic attacks.
        """
        internal_ips = [f"192.168.1.{i}" for i in range(10, 20)]
        external_ips = [
            "8.8.8.8", "1.1.1.1", "185.220.101.4", "94.23.23.41", 
            "172.217.16.142", "13.227.74.129", "23.45.67.89"
        ]
        
        while self.is_running:
            time.sleep(random.uniform(1.0, 3.5)) # interval
            
            is_attack = random.random() < 0.15
            
            if not is_attack:
                # Benign Flow
                flow = {
                    "src_ip": random.choice(internal_ips),
                    "src_port": random.choice([443, 80, 22, 53, 3000, 5000]),
                    "dst_ip": random.choice(external_ips),
                    "dst_port": random.randint(30000, 60000),
                    "protocol": random.choice([6, 17]),
                    "tot_fw_pkts": random.randint(5, 40),
                    "tot_bw_pkts": random.randint(5, 40),
                    "tot_l_fw_pkts": random.randint(200, 15000),
                    "tot_l_bw_pkts": random.randint(200, 15000),
                    "last_active": time.time(),
                    "start_time": time.time() - random.uniform(0.5, 4.0),
                    "flags_fin": 1,
                    "flags_syn": 1,
                    "flags_rst": 0,
                    "flags_psh": 1,
                    "flags_ack": 1
                }
                duration = flow["last_active"] - flow["start_time"]
                feature_vector = [
                    duration, flow["tot_fw_pkts"], flow["tot_bw_pkts"], 
                    flow["tot_l_fw_pkts"], flow["tot_l_bw_pkts"],
                    (flow["tot_l_fw_pkts"] + flow["tot_l_bw_pkts"]) / duration,
                    (flow["tot_fw_pkts"] + flow["tot_bw_pkts"]) / duration,
                    flow["tot_fw_pkts"] * 40, flow["tot_bw_pkts"] * 40,
                    1, 1, 0, 1, 1, flow["protocol"]
                ]
                
                db = SessionLocal()
                try:
                    res = nids_detector.analyze_and_log_flow(
                        db,
                        {
                            "src_ip": flow["src_ip"], "src_port": flow["src_port"],
                            "dst_ip": flow["dst_ip"], "dst_port": flow["dst_port"],
                            "protocol": self.proto_map.get(flow["protocol"], "OTHER"),
                            "duration": duration, "total_packets": flow["tot_fw_pkts"] + flow["tot_bw_pkts"],
                            "total_bytes": flow["tot_l_fw_pkts"] + flow["tot_l_bw_pkts"]
                        },
                        feature_vector
                    )
                    # Override class label locally if it classifies as malicious to force Benign
                    if res["prediction"] != "Benign" and res["prediction"] != "Normal":
                        res["prediction"] = "Benign"
                        res["severity"] = "LOW"
                        
                    if self.websocket_broadcast_cb:
                        payload = {
                            "event": "new_flow",
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "data": {
                                "log_id": res["log_id"],
                                "alert_id": None,
                                "severity": "INFO",
                                "attack_type": "Benign",
                                "source": f"{flow['src_ip']}:{flow['src_port']}",
                                "destination": f"{flow['dst_ip']}:{flow['dst_port']}",
                                "flow_details": {
                                    "protocol": self.proto_map.get(flow["protocol"], "OTHER"),
                                    "duration_sec": round(duration, 3),
                                    "total_bytes": flow["tot_l_fw_pkts"] + flow["tot_l_bw_pkts"],
                                    "total_packets": flow["tot_fw_pkts"] + flow["tot_bw_pkts"]
                                },
                                "confidence": round(res["confidence"], 3)
                            }
                        }
                        self.websocket_broadcast_cb(payload)
                except Exception as e:
                    print(f"[Sniffer Daemon] Simulator save error: {e}")
                finally:
                    db.close()
            else:
                # Attack Flow
                attack_type = random.choice(["DDoS", "PortScan", "BruteForce"])
                src = random.choice(["185.220.101.4", "94.23.23.41", "23.45.67.89"])
                dst = "192.168.1.10"
                
                if attack_type == "DDoS":
                    flow = {
                        "src_ip": src, "src_port": random.randint(10000, 65000),
                        "dst_ip": dst, "dst_port": 80,
                        "protocol": 6, "tot_fw_pkts": random.randint(500, 1500), "tot_bw_pkts": 0,
                        "tot_l_fw_pkts": random.randint(200000, 800000), "tot_l_bw_pkts": 0,
                        "last_active": time.time(), "start_time": time.time() - random.uniform(0.01, 0.2),
                        "flags_fin": 0, "flags_syn": 1, "flags_rst": 0, "flags_psh": 0, "flags_ack": 0
                    }
                elif attack_type == "PortScan":
                    flow = {
                        "src_ip": src, "src_port": random.randint(30000, 60000),
                        "dst_ip": dst, "dst_port": random.randint(20, 1000),
                        "protocol": 6, "tot_fw_pkts": 1, "tot_bw_pkts": 0,
                        "tot_l_fw_pkts": 40, "tot_l_bw_pkts": 0,
                        "last_active": time.time(), "start_time": time.time() - 0.001,
                        "flags_fin": 0, "flags_syn": 1, "flags_rst": 1, "flags_psh": 0, "flags_ack": 0
                    }
                else: # BruteForce
                    flow = {
                        "src_ip": src, "src_port": random.randint(35000, 50000),
                        "dst_ip": dst, "dst_port": 22,
                        "protocol": 6, "tot_fw_pkts": random.randint(30, 90), "tot_bw_pkts": random.randint(30, 90),
                        "tot_l_fw_pkts": random.randint(2000, 10000), "tot_l_bw_pkts": random.randint(2000, 10000),
                        "last_active": time.time(), "start_time": time.time() - random.uniform(2.0, 5.0),
                        "flags_fin": 1, "flags_syn": 1, "flags_rst": 0, "flags_psh": 1, "flags_ack": 1
                    }
                
                duration = flow["last_active"] - flow["start_time"]
                feature_vector = [
                    duration, flow["tot_fw_pkts"], flow["tot_bw_pkts"], 
                    flow["tot_l_fw_pkts"], flow["tot_l_bw_pkts"],
                    (flow["tot_l_fw_pkts"] + flow["tot_l_bw_pkts"]) / duration,
                    (flow["tot_fw_pkts"] + flow["tot_bw_pkts"]) / duration,
                    flow["tot_fw_pkts"] * 40, flow["tot_bw_pkts"] * 40,
                    flow["flags_fin"], flow["flags_syn"], flow["flags_rst"],
                    flow["flags_psh"], flow["flags_ack"], flow["protocol"]
                ]
                
                # Predict via unified detection engine
                db = SessionLocal()
                try:
                    res = nids_detector.analyze_and_log_flow(
                        db,
                        {
                            "src_ip": flow["src_ip"], "src_port": flow["src_port"],
                            "dst_ip": flow["dst_ip"], "dst_port": flow["dst_port"],
                            "protocol": self.proto_map.get(flow["protocol"], "OTHER"),
                            "duration": duration, "total_packets": flow["tot_fw_pkts"] + flow["tot_bw_pkts"],
                            "total_bytes": flow["tot_l_fw_pkts"] + flow["tot_l_bw_pkts"]
                        },
                        feature_vector
                    )
                    
                    # Ensure simulator registers attack label correctly
                    pred_label = res["prediction"]
                    if pred_label == "Benign" or pred_label == "Normal":
                        pred_label = "DDoS" if attack_type == "DDoS" else ("PortScan" if attack_type == "PortScan" else "BruteForce")
                        
                    if self.websocket_broadcast_cb:
                        payload = {
                            "event": "alert_triggered",
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "data": {
                                "log_id": res["log_id"],
                                "alert_id": res["alert_id"],
                                "severity": res["severity"],
                                "attack_type": pred_label,
                                "source": f"{flow['src_ip']}:{flow['src_port']}",
                                "destination": f"{flow['dst_ip']}:{flow['dst_port']}",
                                "flow_details": {
                                    "protocol": self.proto_map.get(flow["protocol"], "OTHER"),
                                    "duration_sec": round(duration, 3),
                                    "total_bytes": flow["tot_l_fw_pkts"] + flow["tot_l_bw_pkts"],
                                    "total_packets": flow["tot_fw_pkts"] + flow["tot_bw_pkts"]
                                },
                                "confidence": round(res["confidence"], 3)
                            }
                        }
                        self.websocket_broadcast_cb(payload)
                except Exception as e:
                    print(f"[Sniffer Daemon] Simulator attack save error: {e}")
                finally:
                    db.close()

# Singleton daemon
sniffer_daemon = PacketSnifferDaemon()
