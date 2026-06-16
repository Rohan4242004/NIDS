import { useEffect, useState } from 'react';
import { Zap } from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, Cell, XAxis, YAxis, CartesianGrid, Tooltip, PieChart, Pie, Legend } from 'recharts';
import { dashboardService, alertsService } from '../services/api';

const PIE_COLORS = ['#ef4444', '#f97316', '#3b82f6', '#f59e0b', '#8b5cf6', '#10b981'];
const BAR_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#10b981'
};

const getServiceFromPort = (port) => {
  const mappings = {
    80: 'HTTP (Web Traffic)',
    443: 'HTTPS (Secure Web)',
    22: 'SSH (Remote Login)',
    21: 'FTP (File Transfer)',
    23: 'Telnet (Unencrypted Admin)',
    53: 'DNS (Name Resolution)',
    445: 'SMB (Active Directory)',
    3306: 'MySQL (Database)',
    5000: 'Flask/Vite Development'
  };
  return mappings[port] || 'Unknown Service';
};

const AttackAnalytics = () => {
  const [loading, setLoading] = useState(true);
  const [pieData, setPieData] = useState([]);
  const [barData, setBarData] = useState([]);
  const [topPorts, setTopPorts] = useState([]);
  const [topAttackers, setTopAttackers] = useState([]);

  const fetchAnalyticsData = async () => {
    setLoading(true);
    try {
      // 1. Fetch dashboard summaries
      const summary = await dashboardService.getSummary();
      
      // Filter out 'Benign' from threat pie chart to focus strictly on threat distribution
      const threatsOnly = (summary.threat_distribution || []).filter(item => item.name !== 'Benign' && item.name !== 'Normal');
      setPieData(threatsOnly);

      // 2. Fetch recent alerts to compile severity counts & targeted ports
      const alerts = await alertsService.getAlerts('', '', 0, 100);
      
      // Compile severities count
      const severities = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
      const ports = {};
      const attackers = {};

      alerts.forEach(alert => {
        // count severity
        const sev = alert.severity?.toUpperCase() || 'MEDIUM';
        if (sev in severities) {
          severities[sev] += 1;
        }

        // count target ports
        const port = alert.traffic_log?.dst_port;
        if (port) {
          ports[port] = (ports[port] || 0) + 1;
        }

        // count attacker IPs
        const srcIp = alert.traffic_log?.src_ip;
        if (srcIp) {
          attackers[srcIp] = (attackers[srcIp] || 0) + 1;
        }
      });

      // Format severity bar chart data
      const formattedBars = Object.keys(severities).map(key => ({
        name: key,
        count: severities[key],
        fill: BAR_COLORS[key]
      }));
      setBarData(formattedBars);

      // Format top ports table data (sort desc)
      const formattedPorts = Object.keys(ports).map(p => ({
        port: p,
        service: getServiceFromPort(Number(p)),
        count: ports[p]
      })).sort((a, b) => b.count - a.count).slice(0, 5);
      setTopPorts(formattedPorts);

      // Format top attacker IPs table data (sort desc)
      const formattedAttackers = Object.keys(attackers).map(ip => ({
        ip_address: ip,
        count: attackers[ip]
      })).sort((a, b) => b.count - a.count).slice(0, 5);
      setTopAttackers(formattedAttackers);

    } catch (err) {
      console.error('Failed to compile threat analytics: ', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    Promise.resolve().then(() => {
      fetchAnalyticsData();
    });
  }, []);



  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '30px' }}>
      
      {/* Header */}
      <div>
        <h3 style={{ fontSize: '1.4rem', fontWeight: 800 }}>Threat Vector Analytics</h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Deep-dive analysis of threat categories, targeted ports, and malicious hosts.</p>
      </div>

      {loading ? (
        <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-muted)' }}>
          <Zap size={24} className="pulse-dot" color="var(--primary)" />
          <p style={{ marginTop: '10px' }}>Analyzing threat intelligence logs...</p>
        </div>
      ) : (
        <>
          {/* Charts Row */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(450px, 1fr))',
            gap: '20px'
          }}>
            {/* Threat Distribution Pie Chart */}
            <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Attack Class Distribution</h4>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Proportional breakdown of classified security incidents</span>
              </div>
              <div style={{ width: '100%', height: '240px' }}>
                {pieData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={pieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={75}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {pieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-color)', borderRadius: '8px' }} />
                      <Legend verticalAlign="bottom" height={36} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
                    No threat classification records in database.
                  </div>
                )}
              </div>
            </div>

            {/* Severity Level Bar Chart */}
            <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Incident Severity Breakdown</h4>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Volume of security alarms sorted by severity tags</span>
              </div>
              <div style={{ width: '100%', height: '240px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={barData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                    <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={11} />
                    <YAxis stroke="var(--text-muted)" fontSize={11} />
                    <Tooltip contentStyle={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-color)', borderRadius: '8px' }} />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                      {barData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.fill} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* Tables Row */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(450px, 1fr))',
            gap: '20px'
          }}>
            {/* Top targeted ports */}
            <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Top Targeted Ports</h4>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Destination ports targeted by scanned/intruding traffic</span>
              </div>
              <div style={{ overflowX: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
                  <thead>
                    <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-color)' }}>
                      <th style={{ padding: '10px 16px', color: 'var(--text-muted)' }}>PORT</th>
                      <th style={{ padding: '10px 16px', color: 'var(--text-muted)' }}>SERVICE PROFILE</th>
                      <th style={{ padding: '10px 16px', color: 'var(--text-muted)', textAlign: 'right' }}>INCIDENT COUNT</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topPorts.length > 0 ? topPorts.map((row, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border-color)' }}>
                        <td style={{ padding: '10px 16px', fontWeight: 700 }} className="text-mono">{row.port}</td>
                        <td style={{ padding: '10px 16px', color: 'var(--text-secondary)' }}>{row.service}</td>
                        <td style={{ padding: '10px 16px', fontWeight: 800, textAlign: 'right', color: 'var(--primary)' }}>
                          {row.count}
                        </td>
                      </tr>
                    )) : (
                      <tr>
                        <td colSpan="3" style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)' }}>
                          No targeted port data compiled yet.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Most active attackers */}
            <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Top Threat IP Hosts</h4>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>External source IPs responsible for triggering security alerts</span>
              </div>
              <div style={{ overflowX: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
                  <thead>
                    <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-color)' }}>
                      <th style={{ padding: '10px 16px', color: 'var(--text-muted)' }}>SOURCE HOST IP</th>
                      <th style={{ padding: '10px 16px', color: 'var(--text-muted)' }}>LOCATION LOG</th>
                      <th style={{ padding: '10px 16px', color: 'var(--text-muted)', textAlign: 'right' }}>INCIDENT COUNT</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topAttackers.length > 0 ? topAttackers.map((row, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border-color)' }}>
                        <td style={{ padding: '10px 16px', fontWeight: 700 }} className="text-mono">{row.ip_address}</td>
                        <td style={{ padding: '10px 16px', color: 'var(--text-muted)' }}>
                          {row.ip_address.startsWith('192.168.') || row.ip_address.startsWith('10.') ? 'Internal Network' : 'External Host'}
                        </td>
                        <td style={{ padding: '10px 16px', fontWeight: 800, textAlign: 'right', color: 'var(--color-critical)' }}>
                          {row.count}
                        </td>
                      </tr>
                    )) : (
                      <tr>
                        <td colSpan="3" style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)' }}>
                          No malicious hosts logged.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </>
      )}

    </div>
  );
};

export default AttackAnalytics;
