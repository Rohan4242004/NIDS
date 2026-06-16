import { useEffect, useState } from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Trash2, 
  Eye, 
  X
} from 'lucide-react';
import { alertsService } from '../services/api';

const Alerts = () => {
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [loading, setLoading] = useState(true);

  // Filters
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  
  // Modal Edit State
  const [editStatus, setEditStatus] = useState('');
  const [editNotes, setEditNotes] = useState('');

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      const data = await alertsService.getAlerts(statusFilter, severityFilter, 0, 100);
      setAlerts(data);
    } catch (err) {
      console.error('Failed to load alerts: ', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    Promise.resolve().then(() => {
      fetchAlerts();
    });
  }, [statusFilter, severityFilter]);

  const handleOpenDetails = (alert) => {
    setSelectedAlert(alert);
    setEditStatus(alert.status);
    setEditNotes(alert.notes || '');
  };

  const handleSaveAlertChange = async (e) => {
    e.preventDefault();
    try {
      const updated = await alertsService.updateAlert(selectedAlert.id, editStatus, editNotes);
      setAlerts(prev => prev.map(a => a.id === updated.id ? updated : a));
      setSelectedAlert(null);
    } catch (err) {
      alert('Failed to update alert: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleDeleteAlert = async (id, e) => {
    e.stopPropagation(); // prevent modal trigger
    if (!confirm('Are you sure you want to permanently delete this alert record?')) return;
    
    try {
      await alertsService.deleteAlert(id);
      setAlerts(prev => prev.filter(a => a.id !== id));
      if (selectedAlert?.id === id) setSelectedAlert(null);
    } catch (err) {
      alert('Failed to delete alert: ' + (err.response?.data?.detail || err.message));
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '30px' }}>
      
      {/* Filters row */}
      <div className="glass-panel" style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: '20px',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <ShieldAlert size={20} color="var(--primary)" />
          <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Filter Intrusion Records</h4>
        </div>
        
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          {/* Status filter dropdown */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            style={{
              padding: '8px 16px',
              backgroundColor: 'var(--bg-primary)',
              border: '1px solid var(--border-color)',
              borderRadius: '8px',
              color: 'var(--text-primary)',
              fontSize: '0.85rem',
              cursor: 'pointer',
              outline: 'none'
            }}
          >
            <option value="">All Resolution Statuses</option>
            <option value="UNRESOLVED">Unresolved</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="RESOLVED">Resolved</option>
          </select>

          {/* Severity filter dropdown */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            style={{
              padding: '8px 16px',
              backgroundColor: 'var(--bg-primary)',
              border: '1px solid var(--border-color)',
              borderRadius: '8px',
              color: 'var(--text-primary)',
              fontSize: '0.85rem',
              cursor: 'pointer',
              outline: 'none'
            }}
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div style={{ overflowX: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-color)' }}>
                <th style={{ padding: '14px 16px', color: 'var(--text-muted)' }}>TIMESTAMP</th>
                <th style={{ padding: '14px 16px', color: 'var(--text-muted)' }}>SEVERITY</th>
                <th style={{ padding: '14px 16px', color: 'var(--text-muted)' }}>CLASSIFICATION</th>
                <th style={{ padding: '14px 16px', color: 'var(--text-muted)' }}>SOURCE IP</th>
                <th style={{ padding: '14px 16px', color: 'var(--text-muted)' }}>DESTINATION</th>
                <th style={{ padding: '14px 16px', color: 'var(--text-muted)' }}>RESOLUTION</th>
                <th style={{ padding: '14px 16px', color: 'var(--text-muted)', textAlign: 'right' }}>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {!loading && alerts.length > 0 ? alerts.map((alert) => {
                let badgeClass = 'badge-medium';
                if (alert.severity === 'CRITICAL') badgeClass = 'badge-critical';
                if (alert.severity === 'HIGH') badgeClass = 'badge-high';
                if (alert.severity === 'LOW') badgeClass = 'badge-low';

                let statusBadge = 'rgba(239, 68, 68, 0.1)';
                let statusColor = 'var(--color-critical)';
                if (alert.status === 'INVESTIGATING') {
                  statusBadge = 'rgba(245, 158, 11, 0.1)';
                  statusColor = 'var(--color-medium)';
                } else if (alert.status === 'RESOLVED') {
                  statusBadge = 'rgba(16, 185, 129, 0.1)';
                  statusColor = 'var(--color-benign)';
                }

                return (
                  <tr 
                    key={alert.id} 
                    onClick={() => handleOpenDetails(alert)}
                    style={{ 
                      borderBottom: '1px solid var(--border-color)', 
                      cursor: 'pointer',
                      transition: 'var(--transition)'
                    }}
                    onMouseOver={(e) => e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.01)'}
                    onMouseOut={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                  >
                    <td style={{ padding: '14px 16px', color: 'var(--text-secondary)' }} className="text-mono">
                      {new Date(alert.created_at).toLocaleString()}
                    </td>
                    <td style={{ padding: '14px 16px' }}>
                      <span className={`badge ${badgeClass}`}>{alert.severity}</span>
                    </td>
                    <td style={{ padding: '14px 16px', fontWeight: 700, color: 'var(--text-primary)' }}>
                      {alert.attack_type?.name || 'Unknown Threat'}
                    </td>
                    <td style={{ padding: '14px 16px', fontWeight: 600 }} className="text-mono">
                      {alert.traffic_log?.src_ip}:{alert.traffic_log?.src_port}
                    </td>
                    <td style={{ padding: '14px 16px' }} className="text-mono">
                      {alert.traffic_log?.dst_ip}:{alert.traffic_log?.dst_port}
                    </td>
                    <td style={{ padding: '14px 16px' }}>
                      <span style={{
                        padding: '4px 10px',
                        borderRadius: '9999px',
                        fontSize: '0.75rem',
                        fontWeight: 700,
                        backgroundColor: statusBadge,
                        color: statusColor,
                        border: `1px solid ${statusColor}22`,
                        textTransform: 'uppercase'
                      }}>
                        {alert.status}
                      </span>
                    </td>
                    <td style={{ padding: '14px 16px', textAlign: 'right' }}>
                      <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                        <button style={{
                          background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', padding: '4px'
                        }}>
                          <Eye size={16} />
                        </button>
                        <button 
                          onClick={(e) => handleDeleteAlert(alert.id, e)}
                          style={{
                            background: 'none', border: 'none', color: 'var(--color-critical)', cursor: 'pointer', padding: '4px'
                          }}
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              }) : (
                <tr>
                  <td colSpan="7" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    {loading ? 'Querying threat database logs...' : 'No security threats records found matching filters.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Resolution Modal */}
      {selectedAlert && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.75)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100,
          padding: '20px'
        }}>
          <div className="glass-panel" style={{
            width: '100%',
            maxWidth: '600px',
            padding: '30px',
            backgroundColor: 'var(--bg-secondary)',
            position: 'relative'
          }}>
            <button 
              onClick={() => setSelectedAlert(null)}
              style={{
                position: 'absolute',
                top: '20px',
                right: '20px',
                background: 'none',
                border: 'none',
                color: 'var(--text-secondary)',
                cursor: 'pointer'
              }}
            >
              <X size={20} />
            </button>

            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px', borderBottom: '1px solid var(--border-color)', paddingBottom: '16px' }}>
              <AlertTriangle size={24} color="var(--color-critical)" />
              <div>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 800 }}>Threat Classification Report</h3>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Record ID: {selectedAlert.id}</span>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '24px' }}>
              <div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>ATTACK CATEGORY</span>
                <p style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--color-critical)' }}>
                  {selectedAlert.attack_type?.name}
                </p>
              </div>
              <div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>ALERT SEVERITY</span>
                <p style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {selectedAlert.severity}
                </p>
              </div>
              <div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>TRAFFIC ORIGIN (SOURCE)</span>
                <p style={{ fontSize: '0.9rem', fontWeight: 600 }} className="text-mono">
                  {selectedAlert.traffic_log?.src_ip}:{selectedAlert.traffic_log?.src_port}
                </p>
              </div>
              <div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>TARGET DESTINATION</span>
                <p style={{ fontSize: '0.9rem', fontWeight: 600 }} className="text-mono">
                  {selectedAlert.traffic_log?.dst_ip}:{selectedAlert.traffic_log?.dst_port}
                </p>
              </div>
              <div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>PROTOCOL & PORT</span>
                <p style={{ fontSize: '0.9rem', fontWeight: 600 }} className="text-mono">
                  {selectedAlert.traffic_log?.protocol} (Port {selectedAlert.traffic_log?.dst_port})
                </p>
              </div>
              <div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>FLOW STATISTICS</span>
                <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }} className="text-mono">
                  {selectedAlert.traffic_log?.total_packets} pkts | {(selectedAlert.traffic_log?.total_bytes / 1024).toFixed(1)} KB
                </p>
              </div>
            </div>

            {/* Audit History Log */}
            {selectedAlert.history && selectedAlert.history.length > 0 && (
              <div style={{ marginBottom: '24px', borderTop: '1px solid var(--border-color)', paddingTop: '16px' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', display: 'block', marginBottom: '10px' }}>
                  RESOLUTION AUDIT HISTORY
                </span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '160px', overflowY: 'auto', paddingRight: '4px' }}>
                  {selectedAlert.history.map((h, i) => (
                    <div key={i} style={{ fontSize: '0.8rem', backgroundColor: 'var(--bg-primary)', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ 
                          fontWeight: 700, 
                          color: h.status === 'RESOLVED' ? 'var(--color-benign)' : (h.status === 'INVESTIGATING' ? 'var(--color-medium)' : 'var(--color-critical)'),
                          fontSize: '0.75rem'
                        }}>
                          {h.status}
                        </span>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{new Date(h.created_at).toLocaleString()}</span>
                      </div>
                      <p style={{ margin: 0, color: 'var(--text-primary)' }}>{h.notes}</p>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 500 }}>Operator: {h.changed_by}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Edit / Resolution Form */}
            <form onSubmit={handleSaveAlertChange} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>INVESTIGATION STATUS</label>
                <select
                  value={editStatus}
                  onChange={(e) => setEditStatus(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '10px 14px',
                    backgroundColor: 'var(--bg-primary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '8px',
                    color: 'var(--text-primary)',
                    fontSize: '0.9rem',
                    outline: 'none',
                    cursor: 'pointer'
                  }}
                >
                  <option value="UNRESOLVED">Unresolved (Immediate Review Required)</option>
                  <option value="INVESTIGATING">Investigating (SOC Analyst Assigned)</option>
                  <option value="RESOLVED">Resolved (Threat Remediated / Ignored)</option>
                </select>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>ANALYST INVESTIGATION NOTES</label>
                <textarea
                  rows={4}
                  value={editNotes}
                  onChange={(e) => setEditNotes(e.target.value)}
                  placeholder="Record firewall blocking confirmations, trace findings, or false-positive notes here..."
                  style={{
                    width: '100%',
                    padding: '10px 14px',
                    backgroundColor: 'var(--bg-primary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '8px',
                    color: 'var(--text-primary)',
                    fontSize: '0.9rem',
                    outline: 'none',
                    resize: 'none',
                    fontFamily: 'var(--font-sans)'
                  }}
                ></textarea>
              </div>

              <div style={{ display: 'flex', gap: '12px', marginTop: '10px' }}>
                <button
                  type="submit"
                  style={{
                    flex: 1,
                    padding: '12px',
                    backgroundColor: 'var(--primary)',
                    color: '#0b0f19',
                    fontWeight: 700,
                    border: 'none',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    fontSize: '0.9rem',
                    transition: 'var(--transition)'
                  }}
                  onMouseOver={(e) => e.currentTarget.style.backgroundColor = 'var(--primary-hover)'}
                  onMouseOut={(e) => e.currentTarget.style.backgroundColor = 'var(--primary)'}
                >
                  Save Changes
                </button>
                <button
                  type="button"
                  onClick={() => setSelectedAlert(null)}
                  style={{
                    padding: '12px 20px',
                    backgroundColor: 'var(--bg-tertiary)',
                    color: 'var(--text-primary)',
                    fontWeight: 500,
                    border: '1px solid var(--border-color)',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    fontSize: '0.9rem',
                    transition: 'var(--transition)'
                  }}
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Alerts;
