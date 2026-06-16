import { useEffect, useState, useRef } from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Wifi, 
  Clock, 
  AlertTriangle,
  Play,
  Square,
  Network
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  AreaChart, 
  Area, 
  BarChart, 
  Bar, 
  Cell, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  PieChart, 
  Pie 
} from 'recharts';
import { dashboardService, alertsService } from '../services/api';
import { liveSocket } from '../services/websocket';

const PIE_COLORS = ['#ef4444', '#f97316', '#f59e0b', '#3b82f6', '#8b5cf6', '#10b981'];
const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#3b82f6'
};

const RealTimeDashboard = () => {
  const [isPlaying, setIsPlaying] = useState(true);
  const [totalPacketsCount, setTotalPacketsCount] = useState(0);
  const [pps, setPps] = useState(0);
  const [activeConnectionsCount, setActiveConnectionsCount] = useState(0);
  const [totalAttacks, setTotalAttacks] = useState(0);
  const [recentAlerts, setRecentAlerts] = useState([]);
  
  // Real-time metrics histories
  const [ppsHistory, setPpsHistory] = useState([]);
  const [severityTimeline, setSeverityTimeline] = useState([]);
  const [attackDistribution, setAttackDistribution] = useState([]);
  const [topAttackers, setTopAttackers] = useState([]);

  // Refs for tracking accumulator values between ticks
  const isPlayingRef = useRef(true);
  const packetsAccumulator = useRef(0);
  const activeFlowsRef = useRef(new Map()); // Map of source -> timestamp
  const attackCountsRef = useRef({});      // Map of attack_type -> count
  const severityBucketsAccumulator = useRef({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 });
  const attackerAlertCounts = useRef({});   // Map of IP -> count

  const updateAttackDistributionState = () => {
    const formatted = Object.keys(attackCountsRef.current)
      .filter(key => key !== 'Benign' && key !== 'Normal')
      .map(key => ({
        name: key,
        value: attackCountsRef.current[key]
      }));
    setAttackDistribution(formatted);
  };

  const updateTopAttackersState = () => {
    const formatted = Object.keys(attackerAlertCounts.current)
      .map(ip => ({
        ip,
        count: attackerAlertCounts.current[ip]
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
    setTopAttackers(formatted);
  };

  const playNotificationSound = (severity) => {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      if (ctx.state === 'suspended') {
        ctx.close().catch(() => {});
        return;
      }
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      
      osc.type = 'sine';
      let freq = 440;
      let duration = 0.15;
      
      if (severity === 'CRITICAL') {
        freq = 880;
        duration = 0.35;
        osc.type = 'sawtooth';
      } else if (severity === 'HIGH') {
        freq = 660;
        duration = 0.25;
      }
      
      osc.frequency.setValueAtTime(freq, ctx.currentTime);
      gain.gain.setValueAtTime(0.1, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + duration);
      
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.onended = () => {
        ctx.close().catch(() => {});
      };
      osc.start();
      osc.stop(ctx.currentTime + duration);
    } catch {
      // Audio autoplay restrictions bypass
    }
  };

  // Prime initial state with historical data from endpoints
  const primeDashboardData = async () => {
    try {
      // Get dashboard aggregate totals
      const summary = await dashboardService.getSummary();
      setTotalAttacks(summary.active_threats || 0);

      // Load pie chart distribution
      const initialPie = (summary.threat_distribution || []).map(item => {
        attackCountsRef.current[item.name] = item.value;
        return { name: item.name, value: item.value };
      });
      setAttackDistribution(initialPie.filter(item => item.name !== 'Benign' && item.name !== 'Normal'));

      // Get recent alerts
      const alerts = await alertsService.getAlerts('', '', 0, 50);
      
      // Compute top attacker counts
      const attackers = {};
      const items = [];
      alerts.forEach(a => {
        const ip = a.traffic_log?.src_ip || 'Unknown';
        if (a.attack_type?.name !== 'Benign') {
          attackers[ip] = (attackers[ip] || 0) + 1;
        }

        // Format recent alerts listing
        items.push({
          timestamp: a.created_at,
          attack_type: a.attack_type?.name || 'Invasion',
          severity: a.severity,
          source: a.traffic_log ? `${a.traffic_log.src_ip}:${a.traffic_log.src_port}` : '0.0.0.0',
          destination: a.traffic_log ? `${a.traffic_log.dst_ip}:${a.traffic_log.dst_port}` : '0.0.0.0',
          confidence: a.prediction_id ? 0.95 : 0.85, // estimate confidence if not present
          flow_details: {
            protocol: a.traffic_log?.protocol || 'TCP',
            total_bytes: a.traffic_log?.total_bytes || 0,
            total_packets: a.traffic_log?.total_packets || 0
          }
        });
      });

      setRecentAlerts(items.slice(0, 10));
      attackerAlertCounts.current = attackers;
      updateTopAttackersState();

      // Pre-fill dummy/flat timeline for charts
      const prefilledPPS = [];
      const prefilledSeverity = [];
      for (let i = 15; i >= 0; i--) {
        const t = new Date(Date.now() - i * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        prefilledPPS.push({ time: t, pps: 0 });
      }
      for (let i = 10; i >= 0; i--) {
        const t = new Date(Date.now() - i * 2000).toLocaleTimeString([], { minute: '2-digit', second: '2-digit' });
        prefilledSeverity.push({ time: t, Critical: 0, High: 0, Medium: 0, Low: 0 });
      }
      setPpsHistory(prefilledPPS);
      setSeverityTimeline(prefilledSeverity);

    } catch (err) {
      console.error('Failed to load initial real-time dashboard data:', err);
    }
  };

  useEffect(() => {
    // 1. Fetch historical data to prime the charts
    Promise.resolve().then(() => {
      primeDashboardData();
    });

    // 2. Setup WebSocket Live listeners
    const handleNewFlow = (data, timestamp) => {
      if (!isPlayingRef.current) return;
      
      const flow = {
        ...data,
        timestamp: timestamp || new Date().toISOString()
      };
      // Accumulate packets
      const packets = flow.flow_details?.total_packets || 1;
      packetsAccumulator.current += packets;
      setTotalPacketsCount(prev => prev + packets);

      // Track active connection
      if (flow.source) {
        activeFlowsRef.current.set(flow.source, Date.now());
      }
    };

    const handleAlertTriggered = (data, timestamp) => {
      if (!isPlayingRef.current) return;
      
      const alert = {
        ...data,
        timestamp: timestamp || new Date().toISOString()
      };
      // Increment total packets too
      const packets = alert.flow_details?.total_packets || 1;
      packetsAccumulator.current += packets;
      setTotalPacketsCount(prev => prev + packets);

      // Track active connection
      if (alert.source) {
        activeFlowsRef.current.set(alert.source, Date.now());
      }

      // Increment total attacks
      setTotalAttacks(prev => prev + 1);

      // Update attack type counts
      const attackType = alert.attack_type || 'Unknown';
      attackCountsRef.current[attackType] = (attackCountsRef.current[attackType] || 0) + 1;
      updateAttackDistributionState();

      // Accumulate severity for the current 2-second time bucket
      const severity = alert.severity?.toUpperCase() || 'MEDIUM';
      if (severity in severityBucketsAccumulator.current) {
        severityBucketsAccumulator.current[severity] += 1;
      }

      // Track Attacker IP (remove port)
      if (alert.source) {
        const ip = alert.source.split(':')[0];
        attackerAlertCounts.current[ip] = (attackerAlertCounts.current[ip] || 0) + 1;
        updateTopAttackersState();
      }

      // Prepend to recent alerts
      setRecentAlerts(prev => [alert, ...prev].slice(0, 15));
      playNotificationSound(severity);
    };

    const offFlow = liveSocket.addEventListener('new_flow', handleNewFlow);
    const offAlert = liveSocket.addEventListener('alert_triggered', handleAlertTriggered);

    // 3. Ticking Timer (Runs every 1 second)
    const tickInterval = setInterval(() => {
      if (!isPlayingRef.current) return;

      // Calculate Packets Per Second
      const currentPackets = packetsAccumulator.current;
      setPps(currentPackets);
      packetsAccumulator.current = 0; // reset for next second

      // Append to PPS History (max 20 entries)
      const nowStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      setPpsHistory(prev => {
        const copy = [...prev];
        if (copy.length >= 20) copy.shift();
        copy.push({ time: nowStr, pps: currentPackets });
        return copy;
      });

      // Clear inactive connections (older than 10 seconds)
      const now = Date.now();
      activeFlowsRef.current.forEach((timestamp, source, map) => {
        if (now - timestamp > 10000) {
          map.delete(source);
        }
      });
      setActiveConnectionsCount(activeFlowsRef.current.size);

    }, 1000);

    // 4. Severity buckets aggregation timer (ticks every 2 seconds to make graph readable)
    const severityInterval = setInterval(() => {
      if (!isPlayingRef.current) return;

      const currentSec = new Date().toLocaleTimeString([], { minute: '2-digit', second: '2-digit' });
      const bucket = { ...severityBucketsAccumulator.current };
      
      // Reset accumulator
      severityBucketsAccumulator.current = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

      setSeverityTimeline(prev => {
        const copy = [...prev];
        if (copy.length >= 15) copy.shift();
        copy.push({
          time: currentSec,
          Critical: bucket.CRITICAL,
          High: bucket.HIGH,
          Medium: bucket.MEDIUM,
          Low: bucket.LOW
        });
        return copy;
      });
    }, 2000);

    return () => {
      offFlow();
      offAlert();
      clearInterval(tickInterval);
      clearInterval(severityInterval);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '30px' }} className="animate-fade-in">
      
      {/* Upper Panel Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ fontSize: '1.45rem', fontWeight: 800 }}>Real-Time Ingestion Telemetry</h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
            Live analytics dashboard displaying socket buffers, connections throughput and malicious ingress activities.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '12px' }}>
          <button 
            onClick={() => {
              setIsPlaying(prev => {
                const nextVal = !prev;
                isPlayingRef.current = nextVal;
                return nextVal;
              });
            }}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              backgroundColor: isPlaying ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)',
              color: isPlaying ? 'var(--color-critical)' : 'var(--color-benign)',
              border: isPlaying ? '1px solid rgba(239, 68, 68, 0.2)' : '1px solid rgba(16, 185, 129, 0.2)',
              borderRadius: '8px',
              padding: '10px 18px',
              fontWeight: 700,
              fontSize: '0.85rem',
              cursor: 'pointer',
              transition: 'var(--transition)'
            }}
          >
            {isPlaying ? (
              <>
                <Square size={16} /> Pause Stream
              </>
            ) : (
              <>
                <Play size={16} fill="currentColor" /> Resume Stream
              </>
            )}
          </button>
          
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            backgroundColor: isPlaying ? 'rgba(16, 185, 129, 0.05)' : 'rgba(255, 255, 255, 0.02)',
            border: isPlaying ? '1px solid rgba(16, 185, 129, 0.15)' : '1px solid var(--border-color)',
            padding: '8px 16px',
            borderRadius: '8px',
            color: isPlaying ? 'var(--color-benign)' : 'var(--text-secondary)',
            fontSize: '0.85rem',
            fontWeight: 600
          }} className={isPlaying ? 'pulse-dot' : ''}>
            <Wifi size={16} />
            {isPlaying ? 'WebSocket: Connected' : 'WebSocket: Paused'}
          </div>
        </div>
      </div>

      {/* Real-time KPI Metric grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '20px'
      }}>
        {/* Packets per second */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '8px', position: 'relative' }}>
          <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
            PACKETS PER SECOND (PPS)
          </span>
          <h3 style={{ fontSize: '2.2rem', fontWeight: 800, color: 'var(--primary)', letterSpacing: '-1px' }} className="text-mono">
            {pps.toLocaleString()}
          </h3>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <Activity size={12} color="var(--primary)" /> Calculated in 1s window
          </span>
        </div>

        {/* Active connections */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
            ACTIVE CONCURRENT HOSTS
          </span>
          <h3 style={{ fontSize: '2.2rem', fontWeight: 800, color: 'var(--color-benign)', letterSpacing: '-1px' }} className="text-mono">
            {activeConnectionsCount}
          </h3>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <Network size={12} color="var(--color-benign)" /> Unique sources in 10s
          </span>
        </div>

        {/* Total attacks */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
            TOTAL INTRUSIONS BLOCKED
          </span>
          <h3 style={{ fontSize: '2.2rem', fontWeight: 800, color: 'var(--color-critical)', letterSpacing: '-1px' }} className="text-mono">
            {totalAttacks}
          </h3>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <ShieldAlert size={12} color="var(--color-critical)" /> Sum of historic & live attacks
          </span>
        </div>

        {/* Total packets count */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
            ACCUMULATED PACKETS
          </span>
          <h3 style={{ fontSize: '2.2rem', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-1px' }} className="text-mono">
            {totalPacketsCount.toLocaleString()}
          </h3>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <Clock size={12} color="var(--text-muted)" /> Total logs since dashboard boot
          </span>
        </div>
      </div>

      {/* Main real-time timeline charts row */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '7fr 5fr',
        gap: '20px'
      }}>
        {/* Live Ingress Speed chart */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div>
            <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Live Ingress Flow Speed (PPS)</h4>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Packets captured and processed per second timeline</span>
          </div>
          <div style={{ width: '100%', height: '260px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={ppsHistory}>
                <defs>
                  <linearGradient id="colorPPS" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.35}/>
                    <stop offset="95%" stopColor="var(--primary)" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={10} />
                <YAxis stroke="var(--text-muted)" fontSize={10} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-color)', borderRadius: '8px' }} />
                <Area type="monotone" dataKey="pps" stroke="var(--primary)" strokeWidth={2} fillOpacity={1} fill="url(#colorPPS)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Live Attack categories distribution */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div>
            <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Attack Vector Proportions</h4>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Live classified threats breakdown</span>
          </div>
          <div style={{ width: '100%', height: '180px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {attackDistribution.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={attackDistribution}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={70}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {attackDistribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-color)', borderRadius: '8px' }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No malicious threats detected in session yet.</span>
            )}
          </div>
          {/* Custom Pie Legend */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px 12px', fontSize: '0.75rem', justifyContent: 'center' }}>
            {attackDistribution.map((entry, index) => (
              <div key={entry.name} style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: PIE_COLORS[index % PIE_COLORS.length] }}></span>
                <span style={{ color: 'var(--text-secondary)' }}>{entry.name}:</span>
                <span style={{ fontWeight: 600 }}>{entry.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Ingress Timeline and Attack targets IPs */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '7fr 5fr',
        gap: '20px'
      }}>
        {/* Threat Severity stacked timeline */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div>
            <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Threat severity graph timeline</h4>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Volume of alarms categorized by threat severity in 2s buckets</span>
          </div>
          <div style={{ width: '100%', height: '260px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityTimeline}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={10} />
                <YAxis stroke="var(--text-muted)" fontSize={10} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-color)', borderRadius: '8px' }} />
                <Legend verticalAlign="top" height={36} iconType="circle" fontSize={11} />
                <Bar dataKey="Critical" stackId="a" fill={SEVERITY_COLORS.CRITICAL} />
                <Bar dataKey="High" stackId="a" fill={SEVERITY_COLORS.HIGH} />
                <Bar dataKey="Medium" stackId="a" fill={SEVERITY_COLORS.MEDIUM} />
                <Bar dataKey="Low" stackId="a" fill={SEVERITY_COLORS.LOW} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top Attacking IP hosts */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div>
            <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Top Attacking Hosts</h4>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>External/Internal source IPs with highest attack event frequency</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {topAttackers.length > 0 ? topAttackers.map((host) => {
              const maxCount = Math.max(...topAttackers.map(h => h.count), 1);
              const percentage = (host.count / maxCount) * 100;
              return (
                <div key={host.ip} style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem' }}>
                    <span className="text-mono" style={{ fontWeight: 700 }}>{host.ip}</span>
                    <span style={{ color: 'var(--color-critical)', fontWeight: 600 }}>{host.count} Event(s)</span>
                  </div>
                  {/* Progress bar */}
                  <div style={{
                    width: '100%',
                    height: '6px',
                    backgroundColor: 'var(--bg-tertiary)',
                    borderRadius: '3px',
                    overflow: 'hidden'
                  }}>
                    <div style={{
                      width: `${percentage}%`,
                      height: '100%',
                      backgroundColor: 'var(--color-critical)',
                      boxShadow: '0 0 8px var(--color-critical-glow)',
                      borderRadius: '3px',
                      transition: 'width 0.4s ease-out'
                    }}></div>
                  </div>
                </div>
              );
            }) : (
              <div style={{ padding: '40px 0', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                No attackers identified in this monitoring session.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Real-time alerts queue */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div>
          <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Ingressed Threat Log Queue</h4>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Scroll of recent alert events received via live WebSocket stream</span>
        </div>

        <div style={{ overflowX: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-color)' }}>
                <th style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>TIMESTAMP</th>
                <th style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>SOURCE IP:PORT</th>
                <th style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>DESTINATION IP:PORT</th>
                <th style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>PROTOCOL</th>
                <th style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>THREAT ALARM</th>
                <th style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>SEVERITY</th>
                <th style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>CONFIDENCE</th>
              </tr>
            </thead>
            <tbody>
              {recentAlerts.length > 0 ? recentAlerts.map((alert, index) => (
                <tr 
                  key={index}
                  className="animate-fade-in" 
                  style={{ 
                    borderBottom: '1px solid var(--border-color)',
                    backgroundColor: alert.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.03)' : 'rgba(249, 115, 22, 0.02)'
                  }}
                >
                  <td style={{ padding: '10px 14px', color: 'var(--text-secondary)' }} className="text-mono">
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </td>
                  <td style={{ padding: '10px 14px', fontWeight: 700 }} className="text-mono">{alert.source}</td>
                  <td style={{ padding: '10px 14px' }} className="text-mono">{alert.destination}</td>
                  <td style={{ padding: '10px 14px', color: 'var(--primary)', fontWeight: 600 }} className="text-mono">
                    {alert.flow_details?.protocol}
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    <span className={`badge ${
                      alert.severity === 'CRITICAL' ? 'badge-critical' :
                      alert.severity === 'HIGH' ? 'badge-high' :
                      alert.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low'
                    }`} style={{ gap: '4px' }}>
                      <AlertTriangle size={12} />
                      {alert.attack_type}
                    </span>
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    <span className={`badge ${
                      alert.severity === 'CRITICAL' ? 'badge-critical' :
                      alert.severity === 'HIGH' ? 'badge-high' :
                      alert.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low'
                    }`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td style={{ padding: '10px 14px', fontWeight: 800 }} className="text-mono">
                    {(alert.confidence * 100).toFixed(1)}%
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan="7" style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No security threat warnings received in this connection session.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default RealTimeDashboard;
