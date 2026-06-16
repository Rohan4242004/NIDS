/* eslint-disable react-hooks/set-state-in-effect */
import { useState, useEffect, useCallback } from 'react';
import { 
  Users, 
  ShieldAlert, 
  Lock, 
  Activity, 
  Download, 
  AlertTriangle, 
  Trash2, 
  Plus, 
  CheckCircle, 
  Server, 
  Clock, 
  Database
} from 'lucide-react';
import { 
  usersService, 
  alertsService, 
  systemService, 
  reportsService, 
  authService 
} from '../services/api';

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#3b82f6'
};

const Admin = () => {
  const [activeTab, setActiveTab] = useState('users');
  const [me, setMe] = useState(null);

  // Users state
  const [users, setUsers] = useState([]);
  const [newUser, setNewUser] = useState({ username: '', email: '', password: '', role: 'operator' });
  const [userError, setUserError] = useState('');
  const [userSuccess, setUserSuccess] = useState('');

  // Alerts state
  const [alerts, setAlerts] = useState([]);
  const [alertFilterStatus, setAlertFilterStatus] = useState('');
  const [alertFilterSeverity, setAlertFilterSeverity] = useState('');
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [resolutionNotes, setResolutionNotes] = useState('');
  const [resolutionStatus, setResolutionStatus] = useState('RESOLVED');

  // Firewall state
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [newBlock, setNewBlock] = useState({ ip_address: '', blocked_reason: '', expires_at: '' });
  const [blockError, setBlockError] = useState('');
  const [blockSuccess, setBlockSuccess] = useState('');

  // Health state
  const [healthData, setHealthData] = useState(null);
  const [healthLoading, setHealthLoading] = useState(true);

  // Report Export state
  const [exportType, setExportType] = useState('alerts');
  const [exportFormat, setExportFormat] = useState('csv');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [exportLoading, setExportLoading] = useState(false);
  const [exportError, setExportError] = useState('');
  const [exportSuccess, setExportSuccess] = useState('');

  // --- INITIAL LOADING ---
  useEffect(() => {
    authService.getMe().then(setMe).catch(() => {});
  }, []);

  // Fetch Users
  const fetchUsers = useCallback(async () => {
    try {
      const data = await usersService.getUsers();
      setUsers(data);
    } catch {
      setUserError('Failed to fetch NIDS user database.');
    }
  }, []);

  // Fetch Alerts
  const fetchAlerts = useCallback(async () => {
    try {
      const data = await alertsService.getAlerts(alertFilterStatus, alertFilterSeverity, 0, 100);
      setAlerts(data);
    } catch {
      // Failed silently
    }
  }, [alertFilterStatus, alertFilterSeverity]);

  // Fetch Firewall blocked IPs
  const fetchBlockedIPs = useCallback(async () => {
    try {
      const data = await alertsService.getBlockedIPs();
      setBlockedIPs(data);
    } catch {
      setBlockError('Failed to retrieve active firewall blocks.');
    }
  }, []);

  // Fetch Health diagnostics
  const fetchHealth = useCallback(async () => {
    try {
      const data = await systemService.getHealth();
      setHealthData(data);
      setHealthLoading(false);
    } catch {
      setHealthLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === 'users') {
      fetchUsers();
    } else if (activeTab === 'alerts') {
      fetchAlerts();
    } else if (activeTab === 'firewall') {
      fetchBlockedIPs();
    } else if (activeTab === 'health') {
      fetchHealth();
    }
  }, [activeTab, fetchUsers, fetchAlerts, fetchBlockedIPs, fetchHealth]);

  // Dynamic poll for system diagnostics (only when health tab is open)
  useEffect(() => {
    if (activeTab !== 'health') return;
    const interval = setInterval(fetchHealth, 5000);
    return () => clearInterval(interval);
  }, [activeTab, fetchHealth]);

  // --- ACTIONS ---

  // Create User
  const handleCreateUser = async (e) => {
    e.preventDefault();
    setUserError('');
    setUserSuccess('');
    try {
      await authService.register(
        newUser.username, 
        newUser.email, 
        newUser.password, 
        newUser.role
      );
      setUserSuccess(`Successfully registered NIDS user ${newUser.username}!`);
      setNewUser({ username: '', email: '', password: '', role: 'operator' });
      fetchUsers();
    } catch (err) {
      setUserError(err.response?.data?.detail || 'Failed to create user account.');
    }
  };

  // Update Role
  const handleUpdateRole = async (userId, newRole) => {
    try {
      await usersService.updateUserRole(userId, newRole);
      fetchUsers();
      setUserSuccess('User role successfully updated.');
    } catch (err) {
      setUserError(err.response?.data?.detail || 'Failed to modify role.');
    }
  };

  // Delete User
  const handleDeleteUser = async (userId) => {
    if (!confirm('Are you sure you want to permanently delete this user account?')) return;
    try {
      await usersService.deleteUser(userId);
      fetchUsers();
      setUserSuccess('User successfully removed from system.');
    } catch (err) {
      setUserError(err.response?.data?.detail || 'Deletion failed.');
    }
  };

  // Resolve Alert
  const handleResolveAlert = async (e) => {
    e.preventDefault();
    if (!selectedAlert) return;
    try {
      await alertsService.updateAlert(selectedAlert.id, resolutionStatus, resolutionNotes);
      fetchAlerts();
      setSelectedAlert(null);
      setResolutionNotes('');
    } catch {
      // error ignored
    }
  };

  // Delete Alert
  const handleDeleteAlert = async (alertId) => {
    if (!confirm('Permanently purge this security alert from NIDS history?')) return;
    try {
      await alertsService.deleteAlert(alertId);
      fetchAlerts();
      if (selectedAlert?.id === alertId) setSelectedAlert(null);
    } catch {
      // error ignored
    }
  };

  // Create IP Block
  const handleBlockIP = async (e) => {
    e.preventDefault();
    setBlockError('');
    setBlockSuccess('');
    try {
      await alertsService.blockIP(
        newBlock.ip_address, 
        newBlock.blocked_reason, 
        newBlock.expires_at || undefined
      );
      setBlockSuccess(`Active firewall rule established for ${newBlock.ip_address}.`);
      setNewBlock({ ip_address: '', blocked_reason: '', expires_at: '' });
      fetchBlockedIPs();
    } catch (err) {
      setBlockError(err.response?.data?.detail || 'Firewall action failed.');
    }
  };

  // Unblock IP
  const handleUnblockIP = async (id, ip) => {
    if (!confirm(`Revoke firewall block rules for ${ip}?`)) return;
    try {
      await alertsService.unblockIP(id);
      fetchBlockedIPs();
      setBlockSuccess(`Revoked block rule for ${ip}.`);
    } catch {
      setBlockError('Failed to unblock IP address.');
    }
  };

  // Export Report Stream
  const handleExportReport = async (e) => {
    e.preventDefault();
    setExportError('');
    setExportSuccess('');
    setExportLoading(true);

    try {
      const blob = await reportsService.exportReport(
        exportType, 
        exportFormat, 
        startDate, 
        endDate
      );
      
      const fileUrl = window.URL.createObjectURL(new Blob([blob]));
      const link = document.createElement('a');
      link.href = fileUrl;
      
      const formattedDate = new Date().toISOString().slice(0, 10);
      link.setAttribute('download', `nids_${exportType}_report_${formattedDate}.${exportFormat}`);
      document.body.appendChild(link);
      link.click();
      
      link.parentNode.removeChild(link);
      setExportSuccess('Report successfully compiled and downloaded.');
    } catch {
      setExportError('Export compiling failed. Verify filter values.');
    } finally {
      setExportLoading(false);
    }
  };

  const tabs = [
    { id: 'users', name: 'User Management', icon: Users },
    { id: 'alerts', name: 'Alert Management', icon: ShieldAlert },
    { id: 'firewall', name: 'Firewall Blocks', icon: Lock },
    { id: 'health', name: 'Diagnostics', icon: Activity },
    { id: 'export', name: 'Reports Center', icon: Download }
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '30px' }} className="animate-fade-in">
      <div>
        <h3 style={{ fontSize: '1.45rem', fontWeight: 800 }}>Administrative Control Center</h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
          Configure user accounts, resolve security anomalies, inspect cluster health gauges, and download CSV reports.
        </p>
      </div>

      {/* Tabs Switcher Navigation */}
      <div style={{
        display: 'flex',
        borderBottom: '1px solid var(--border-color)',
        gap: '24px',
        paddingBottom: '2px'
      }}>
        {tabs.map(tab => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '12px 6px',
                border: 'none',
                borderBottom: isActive ? '3px solid var(--primary)' : '3px solid transparent',
                backgroundColor: 'transparent',
                color: isActive ? 'var(--primary)' : 'var(--text-secondary)',
                fontWeight: isActive ? 700 : 500,
                fontSize: '0.9rem',
                cursor: 'pointer',
                transition: 'var(--transition)'
              }}
            >
              <Icon size={16} />
              {tab.name}
            </button>
          );
        })}
      </div>

      {/* TABS CONTAINER */}
      <div>
        {/* 1. USER MANAGEMENT */}
        {activeTab === 'users' && (
          <div style={{ display: 'grid', gridTemplateColumns: '7fr 5fr', gap: '20px' }}>
            <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Registered Operators</h4>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Configure credentials, privileges, and operational accounts</span>
              </div>

              {userSuccess && <div style={{ color: 'var(--color-benign)', fontSize: '0.8rem', fontWeight: 600 }}>{userSuccess}</div>}
              {userError && <div style={{ color: 'var(--color-critical)', fontSize: '0.8rem', fontWeight: 600 }}>{userError}</div>}

              <div style={{ overflowX: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
                  <thead>
                    <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-color)' }}>
                      <th style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>USERNAME</th>
                      <th style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>EMAIL</th>
                      <th style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>ROLE</th>
                      <th style={{ padding: '10px 14px', color: 'var(--text-muted)', textAlign: 'right' }}>ACTIONS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map(u => (
                      <tr key={u.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                        <td style={{ padding: '10px 14px', fontWeight: 700 }}>{u.username}</td>
                        <td style={{ padding: '10px 14px', color: 'var(--text-secondary)' }}>{u.email}</td>
                        <td style={{ padding: '10px 14px' }}>
                          <select
                            value={u.role}
                            disabled={me && me.id === u.id}
                            onChange={(e) => handleUpdateRole(u.id, e.target.value)}
                            style={{
                              backgroundColor: 'var(--bg-tertiary)',
                              color: 'var(--text-primary)',
                              border: '1px solid var(--border-color)',
                              borderRadius: '4px',
                              padding: '4px 8px',
                              fontSize: '0.8rem'
                            }}
                          >
                            <option value="operator">Operator</option>
                            <option value="admin">Admin</option>
                          </select>
                        </td>
                        <td style={{ padding: '10px 14px', textAlign: 'right' }}>
                          <button
                            onClick={() => handleDeleteUser(u.id)}
                            disabled={me && me.id === u.id}
                            style={{
                              backgroundColor: 'transparent',
                              border: 'none',
                              color: 'var(--color-critical)',
                              cursor: 'pointer',
                              opacity: me && me.id === u.id ? 0.3 : 1
                            }}
                          >
                            <Trash2 size={16} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* User Registration Form */}
            <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Register NIDS User</h4>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Provision a new system analyst credentials</span>
              </div>

              <form onSubmit={handleCreateUser} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Username</label>
                  <input
                    type="text"
                    required
                    placeholder="Enter unique username"
                    value={newUser.username}
                    onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '8px',
                      padding: '10px',
                      color: 'var(--text-primary)',
                      fontSize: '0.85rem'
                    }}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Email</label>
                  <input
                    type="email"
                    required
                    placeholder="Enter email address"
                    value={newUser.email}
                    onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '8px',
                      padding: '10px',
                      color: 'var(--text-primary)',
                      fontSize: '0.85rem'
                    }}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Initial Password</label>
                  <input
                    type="password"
                    required
                    placeholder="Provide strong credentials"
                    value={newUser.password}
                    onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '8px',
                      padding: '10px',
                      color: 'var(--text-primary)',
                      fontSize: '0.85rem'
                    }}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Administrative Role</label>
                  <select
                    value={newUser.role}
                    onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '8px',
                      padding: '10px',
                      color: 'var(--text-primary)',
                      fontSize: '0.85rem'
                    }}
                  >
                    <option value="operator">Operator (Standard Access)</option>
                    <option value="admin">Administrator (Full Access)</option>
                  </select>
                </div>

                <button
                  type="submit"
                  style={{
                    backgroundColor: 'var(--primary)',
                    color: '#0b0f19',
                    border: 'none',
                    borderRadius: '8px',
                    padding: '12px',
                    fontWeight: 700,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px',
                    marginTop: '10px'
                  }}
                >
                  <Plus size={16} /> Register Account
                </button>
              </form>
            </div>
          </div>
        )}

        {/* 2. ALERT MANAGEMENT */}
        {activeTab === 'alerts' && (
          <div style={{ display: 'grid', gridTemplateColumns: '7fr 5fr', gap: '20px' }}>
            <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Intrusion Severity Logs</h4>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Review alarms and dispatch resolutions</span>
                </div>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <select
                    value={alertFilterStatus}
                    onChange={(e) => setAlertFilterStatus(e.target.value)}
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      color: 'var(--text-primary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '6px',
                      padding: '6px 10px',
                      fontSize: '0.75rem'
                    }}
                  >
                    <option value="">All Statuses</option>
                    <option value="UNRESOLVED">Unresolved</option>
                    <option value="INVESTIGATING">Investigating</option>
                    <option value="RESOLVED">Resolved</option>
                    <option value="FALSE_POSITIVE">False Positive</option>
                  </select>
                  <select
                    value={alertFilterSeverity}
                    onChange={(e) => setAlertFilterSeverity(e.target.value)}
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      color: 'var(--text-primary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '6px',
                      padding: '6px 10px',
                      fontSize: '0.75rem'
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

              <div style={{ overflowX: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
                  <thead>
                    <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-color)' }}>
                      <th style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>TIMESTAMP</th>
                      <th style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>ATTACK TYPE</th>
                      <th style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>SEVERITY</th>
                      <th style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>STATUS</th>
                      <th style={{ padding: '10px 14px', color: 'var(--text-muted)', textAlign: 'right' }}>ACTIONS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.length > 0 ? alerts.map(a => (
                      <tr 
                        key={a.id} 
                        onClick={() => setSelectedAlert(a)}
                        style={{ 
                          borderBottom: '1px solid var(--border-color)',
                          cursor: 'pointer',
                          backgroundColor: selectedAlert && selectedAlert.id === a.id ? 'rgba(6, 182, 212, 0.05)' : 'transparent'
                        }}
                      >
                        <td style={{ padding: '10px 14px', color: 'var(--text-secondary)' }} className="text-mono">
                          {new Date(a.created_at).toLocaleTimeString()}
                        </td>
                        <td style={{ padding: '10px 14px', fontWeight: 600 }}>{a.attack_type?.name || 'Anomaly'}</td>
                        <td style={{ padding: '10px 14px' }}>
                          <span style={{ color: SEVERITY_COLORS[a.severity] || '#f3f4f6', fontWeight: 700 }}>
                            {a.severity}
                          </span>
                        </td>
                        <td style={{ padding: '10px 14px' }}>
                          <span className={`badge ${
                            a.status === 'RESOLVED' ? 'badge-benign' :
                            a.status === 'UNRESOLVED' ? 'badge-critical' : 'badge-medium'
                          }`}>
                            {a.status}
                          </span>
                        </td>
                        <td style={{ padding: '10px 14px', textAlign: 'right' }}>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteAlert(a.id);
                            }}
                            style={{
                              backgroundColor: 'transparent',
                              border: 'none',
                              color: 'var(--color-critical)',
                              cursor: 'pointer'
                            }}
                          >
                            <Trash2 size={16} />
                          </button>
                        </td>
                      </tr>
                    )) : (
                      <tr>
                        <td colSpan="5" style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
                          No alerts correspond to selection.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Alert Resolution Form */}
            <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Incident Action Plan</h4>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Assign resolutions or log analysis overrides</span>
              </div>

              {selectedAlert ? (
                <form onSubmit={handleResolveAlert} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '0.8rem' }}>
                    <div>
                      <span style={{ color: 'var(--text-secondary)' }}>Log ID:</span>
                      <p className="text-mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>#{selectedAlert.log_id}</p>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-secondary)' }}>Source Connection:</span>
                      <p className="text-mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        {selectedAlert.traffic_log ? `${selectedAlert.traffic_log.src_ip}:${selectedAlert.traffic_log.src_port}` : '0.0.0.0'}
                      </p>
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Resolution Action</label>
                    <select
                      value={resolutionStatus}
                      onChange={(e) => setResolutionStatus(e.target.value)}
                      style={{
                        backgroundColor: 'var(--bg-tertiary)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '8px',
                        padding: '10px',
                        color: 'var(--text-primary)',
                        fontSize: '0.85rem'
                      }}
                    >
                      <option value="RESOLVED">Resolved / Blocked</option>
                      <option value="INVESTIGATING">Investigating / Under Review</option>
                      <option value="FALSE_POSITIVE">Flag False Positive</option>
                    </select>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Resolution Notes</label>
                    <textarea
                      required
                      rows={4}
                      placeholder="Describe incident analysis, root cause, or resolution steps..."
                      value={resolutionNotes}
                      onChange={(e) => setResolutionNotes(e.target.value)}
                      style={{
                        backgroundColor: 'var(--bg-tertiary)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '8px',
                        padding: '10px',
                        color: 'var(--text-primary)',
                        fontSize: '0.85rem',
                        fontFamily: 'inherit'
                      }}
                    />
                  </div>

                  <div style={{ display: 'flex', gap: '10px' }}>
                    <button
                      type="submit"
                      style={{
                        flex: 1,
                        backgroundColor: 'var(--primary)',
                        color: '#0b0f19',
                        border: 'none',
                        borderRadius: '8px',
                        padding: '12px',
                        fontWeight: 700,
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '8px'
                      }}
                    >
                      <CheckCircle size={16} /> Resolve Alert
                    </button>
                    <button
                      type="button"
                      onClick={() => setSelectedAlert(null)}
                      style={{
                        backgroundColor: 'transparent',
                        color: 'var(--text-secondary)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '8px',
                        padding: '12px 18px',
                        fontWeight: 600,
                        cursor: 'pointer'
                      }}
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              ) : (
                <div style={{ 
                  padding: '60px 0', 
                  textAlign: 'center', 
                  color: 'var(--text-muted)',
                  fontSize: '0.85rem',
                  border: '1px dashed var(--border-color)',
                  borderRadius: '8px'
                }}>
                  <AlertTriangle size={24} style={{ margin: '0 auto 10px', display: 'block', color: 'var(--text-muted)' }} />
                  Select an alert from the severity logs to assign resolution.
                </div>
              )}
            </div>
          </div>
        )}

        {/* 3. FIREWALL / BLOCKED IP MANAGEMENT */}
        {activeTab === 'firewall' && (
          <div style={{ display: 'grid', gridTemplateColumns: '7fr 5fr', gap: '20px' }}>
            <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Firewall Block Registry</h4>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Host IP addresses blocked due to suspicious classification patterns</span>
              </div>

              {blockSuccess && <div style={{ color: 'var(--color-benign)', fontSize: '0.8rem', fontWeight: 600 }}>{blockSuccess}</div>}
              {blockError && <div style={{ color: 'var(--color-critical)', fontSize: '0.8rem', fontWeight: 600 }}>{blockError}</div>}

              <div style={{ overflowX: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
                  <thead>
                    <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-color)' }}>
                      <th style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>IP ADDRESS</th>
                      <th style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>REASON</th>
                      <th style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>EXPIRES AT</th>
                      <th style={{ padding: '10px 14px', color: 'var(--text-muted)', textAlign: 'right' }}>ACTION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {blockedIPs.length > 0 ? blockedIPs.map(b => (
                      <tr key={b.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                        <td style={{ padding: '10px 14px', fontWeight: 700 }} className="text-mono">{b.ip_address}</td>
                        <td style={{ padding: '10px 14px', color: 'var(--text-secondary)' }}>{b.blocked_reason}</td>
                        <td style={{ padding: '10px 14px', color: 'var(--text-muted)' }} className="text-mono">
                          {b.expires_at ? new Date(b.expires_at).toLocaleString() : 'Permanent'}
                        </td>
                        <td style={{ padding: '10px 14px', textAlign: 'right' }}>
                          <button
                            onClick={() => handleUnblockIP(b.id, b.ip_address)}
                            style={{
                              backgroundColor: 'rgba(16, 185, 129, 0.1)',
                              color: 'var(--color-benign)',
                              border: '1px solid rgba(16, 185, 129, 0.2)',
                              borderRadius: '4px',
                              padding: '4px 10px',
                              fontSize: '0.75rem',
                              fontWeight: 600,
                              cursor: 'pointer'
                            }}
                          >
                            Unblock
                          </button>
                        </td>
                      </tr>
                    )) : (
                      <tr>
                        <td colSpan="4" style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
                          No IP block rules registered in the firewall registry.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Block IP Form */}
            <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Propose Firewall Rule</h4>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Manually flag and isolate target network address</span>
              </div>

              <form onSubmit={handleBlockIP} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>IP Address</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. 198.51.100.42"
                    value={newBlock.ip_address}
                    onChange={(e) => setNewBlock({ ...newBlock, ip_address: e.target.value })}
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '8px',
                      padding: '10px',
                      color: 'var(--text-primary)',
                      fontSize: '0.85rem',
                      fontFamily: 'monospace'
                    }}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Reason for block</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Repeated DDoS pattern anomaly"
                    value={newBlock.blocked_reason}
                    onChange={(e) => setNewBlock({ ...newBlock, blocked_reason: e.target.value })}
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '8px',
                      padding: '10px',
                      color: 'var(--text-primary)',
                      fontSize: '0.85rem'
                    }}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Rule Expiry (Optional)</label>
                  <input
                    type="datetime-local"
                    value={newBlock.expires_at}
                    onChange={(e) => setNewBlock({ ...newBlock, expires_at: e.target.value })}
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '8px',
                      padding: '10px',
                      color: 'var(--text-primary)',
                      fontSize: '0.85rem'
                    }}
                  />
                </div>

                <button
                  type="submit"
                  style={{
                    backgroundColor: 'var(--color-critical)',
                    color: '#f3f4f6',
                    border: 'none',
                    borderRadius: '8px',
                    padding: '12px',
                    fontWeight: 700,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px',
                    marginTop: '10px',
                    boxShadow: '0 0 10px var(--color-critical-glow)'
                  }}
                >
                  <Lock size={16} /> Block IP Address
                </button>
              </form>
            </div>
          </div>
        )}

        {/* 4. DIAGNOSTICS & SYSTEM HEALTH */}
        {activeTab === 'health' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {healthLoading ? (
              <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                Loading clusters telemetry diagnostics...
              </div>
            ) : healthData ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                {/* Upper Health Grid */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px' }}>
                  
                  {/* Database Health Card */}
                  <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>SQL DATABASE NODE</span>
                      <Database size={18} color="var(--primary)" />
                    </div>
                    <h3 style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--primary)' }} className="text-mono">
                      {healthData.database?.latency_ms} ms
                    </h3>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem' }}>
                      <span style={{
                        width: '8px',
                        height: '8px',
                        borderRadius: '50%',
                        backgroundColor: healthData.database?.status === 'HEALTHY' ? 'var(--color-benign)' : 'var(--color-critical)'
                      }} className={healthData.database?.status === 'HEALTHY' ? 'pulse-dot' : ''}></span>
                      <span style={{ color: 'var(--text-secondary)' }}>
                        Status: <b style={{ color: healthData.database?.status === 'HEALTHY' ? 'var(--color-benign)' : 'var(--color-critical)' }}>{healthData.database?.status}</b>
                      </span>
                    </div>
                  </div>

                  {/* Packet Sniffer Health Card */}
                  <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>INGRESS PACKET SNIFFER</span>
                      <Server size={18} color="var(--color-benign)" />
                    </div>
                    <h3 style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--color-benign)' }} className="text-mono">
                      {healthData.sniffer?.active_flows_count} flows
                    </h3>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem' }}>
                      <span style={{
                        width: '8px',
                        height: '8px',
                        borderRadius: '50%',
                        backgroundColor: healthData.sniffer?.status === 'ACTIVE' ? 'var(--color-benign)' : 'var(--color-critical)'
                      }} className={healthData.sniffer?.status === 'ACTIVE' ? 'pulse-dot' : ''}></span>
                      <span style={{ color: 'var(--text-secondary)' }}>
                        Daemon: <b style={{ color: healthData.sniffer?.status === 'ACTIVE' ? 'var(--color-benign)' : 'var(--color-critical)' }}>{healthData.sniffer?.status}</b>
                      </span>
                    </div>
                  </div>

                  {/* System Load Health Card */}
                  <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>SIMULATED INFRASTRUCTURE LOAD</span>
                      <Clock size={18} color="var(--color-medium)" />
                    </div>
                    <h3 style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--color-medium)' }} className="text-mono">
                      {healthData.system?.cpu_percent}% CPU
                    </h3>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem' }}>
                      <span style={{
                        width: '8px',
                        height: '8px',
                        borderRadius: '50%',
                        backgroundColor: 'var(--color-benign)'
                      }} className="pulse-dot"></span>
                      <span style={{ color: 'var(--text-secondary)' }}>
                        Overall Status: <b style={{ color: 'var(--color-benign)' }}>{healthData.status}</b>
                      </span>
                    </div>
                  </div>
                </div>

                {/* Progress Gauges Grid */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                  
                  {/* Memory Usage Details */}
                  <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <div>
                      <h4 style={{ fontSize: '0.9rem', fontWeight: 700 }}>Host Memory Utilization</h4>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Cluster Node RAM consumption allocation</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem' }}>
                      <span>Allocated: <b>{healthData.system?.memory?.used_gb} GB</b> / {healthData.system?.memory?.total_gb} GB</span>
                      <span style={{ fontWeight: 700, color: 'var(--primary)' }}>{healthData.system?.memory?.used_percent}%</span>
                    </div>
                    {/* Progress Bar */}
                    <div style={{ width: '100%', height: '8px', backgroundColor: 'var(--bg-tertiary)', borderRadius: '4px', overflow: 'hidden' }}>
                      <div style={{
                        width: `${healthData.system?.memory?.used_percent}%`,
                        height: '100%',
                        backgroundColor: 'var(--primary)',
                        borderRadius: '4px'
                      }}></div>
                    </div>
                  </div>

                  {/* Disk Space Details */}
                  <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <div>
                      <h4 style={{ fontSize: '0.9rem', fontWeight: 700 }}>Storage Volume Registry</h4>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Available disk partition space on database cluster node</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem' }}>
                      <span>Used Partition: <b>{healthData.system?.disk?.used_gb} GB</b> / {healthData.system?.disk?.total_gb} GB</span>
                      <span style={{ fontWeight: 700, color: 'var(--color-benign)' }}>{healthData.system?.disk?.used_percent}%</span>
                    </div>
                    {/* Progress Bar */}
                    <div style={{ width: '100%', height: '8px', backgroundColor: 'var(--bg-tertiary)', borderRadius: '4px', overflow: 'hidden' }}>
                      <div style={{
                        width: `${healthData.system?.disk?.used_percent}%`,
                        height: '100%',
                        backgroundColor: 'var(--color-benign)',
                        borderRadius: '4px'
                      }}></div>
                    </div>
                  </div>

                </div>
              </div>
            ) : (
              <div style={{ padding: '60px', textAlign: 'center', color: 'var(--color-critical)' }}>
                System diagnostics API returned invalid telemetry payloads. Check connection.
              </div>
            )}
          </div>
        )}

        {/* 5. EXPORT CENTER */}
        {activeTab === 'export' && (
          <div className="glass-panel" style={{ maxWidth: '600px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div>
              <h4 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Report Exporter</h4>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Generate and download database dump filters as spreadsheets or structures</span>
            </div>

            {exportSuccess && <div style={{ color: 'var(--color-benign)', fontSize: '0.85rem', fontWeight: 600 }}>{exportSuccess}</div>}
            {exportError && <div style={{ color: 'var(--color-critical)', fontSize: '0.85rem', fontWeight: 600 }}>{exportError}</div>}

            <form onSubmit={handleExportReport} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                
                {/* Type select */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Log Registry Type</label>
                  <select
                    value={exportType}
                    onChange={(e) => setExportType(e.target.value)}
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '8px',
                      padding: '10px',
                      color: 'var(--text-primary)',
                      fontSize: '0.85rem'
                    }}
                  >
                    <option value="alerts">Security Alarms Log</option>
                    <option value="traffic">Captured Connections Traffic</option>
                  </select>
                </div>

                {/* Format select */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Output Format</label>
                  <select
                    value={exportFormat}
                    onChange={(e) => setExportFormat(e.target.value)}
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '8px',
                      padding: '10px',
                      color: 'var(--text-primary)',
                      fontSize: '0.85rem'
                    }}
                  >
                    <option value="csv">CSV (Spreadsheet/Excel compatible)</option>
                    <option value="json">JSON (Developer/Anomalies structures)</option>
                  </select>
                </div>

              </div>

              {/* Date Filters */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>From Date (Optional)</label>
                  <input
                    type="date"
                    value={startDate}
                    onChange={(e) => setStartDate(e.target.value)}
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '8px',
                      padding: '10px',
                      color: 'var(--text-primary)',
                      fontSize: '0.85rem'
                    }}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>To Date (Optional)</label>
                  <input
                    type="date"
                    value={endDate}
                    onChange={(e) => setEndDate(e.target.value)}
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '8px',
                      padding: '10px',
                      color: 'var(--text-primary)',
                      fontSize: '0.85rem'
                    }}
                  />
                </div>

              </div>

              <button
                type="submit"
                disabled={exportLoading}
                style={{
                  backgroundColor: 'var(--primary)',
                  color: '#0b0f19',
                  border: 'none',
                  borderRadius: '8px',
                  padding: '14px',
                  fontWeight: 700,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                  marginTop: '10px',
                  opacity: exportLoading ? 0.6 : 1
                }}
              >
                <Download size={16} /> 
                {exportLoading ? 'Compiling stream...' : 'Generate & Download Report'}
              </button>
            </form>
          </div>
        )}
      </div>
    </div>
  );
};

export default Admin;
