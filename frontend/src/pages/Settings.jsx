import { useEffect, useState } from 'react';
import { 
  Radio, 
  Binary, 
  Shield, 
  Cpu, 
  Award, 
  CheckCircle, 
  ToggleLeft, 
  ToggleRight, 
  Sparkles, 
  Plus, 
  Trash2, 
  Sliders, 
  Network, 
  RefreshCw, 
  AlertTriangle 
} from 'lucide-react';
import { modelsService, alertsService } from '../services/api';

const Settings = () => {
  const [activeTab, setActiveTab] = useState('sniffer');
  
  // ML Model State
  const [models, setModels] = useState([]);
  const [modelsLoading, setModelsLoading] = useState(true);
  const [activeModel, setActiveModel] = useState(null);

  // Firewall State
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [firewallLoading, setFirewallLoading] = useState(true);
  const [newIP, setNewIP] = useState('');
  const [blockReason, setBlockReason] = useState('');
  const [submittingBlock, setSubmittingBlock] = useState(false);
  const [firewallError, setFirewallError] = useState('');

  // Sniffer State
  const [snifferActive, setSnifferActive] = useState(true);
  const [promiscuousMode, setPromiscuousMode] = useState(true);
  const [selectedInterface, setSelectedInterface] = useState('Ethernet0 (Realtek PCIe GbE)');
  const [filterQuery, setFilterQuery] = useState('ip and (tcp or udp or icmp)');

  // --- ML MODELS ACTIONS ---
  const fetchModels = async () => {
    setModelsLoading(true);
    try {
      const data = await modelsService.getModels();
      setModels(data);
      const active = data.find(m => m.is_active);
      setActiveModel(active || null);
    } catch (err) {
      console.error('Failed to load ML models:', err);
    } finally {
      setModelsLoading(false);
    }
  };

  // --- FIREWALL ACTIONS ---
  const fetchBlockedIPs = async () => {
    setFirewallLoading(true);
    setFirewallError('');
    try {
      const data = await alertsService.getBlockedIPs();
      setBlockedIPs(data);
    } catch (err) {
      console.error('Failed to load blocked IPs:', err);
      setFirewallError('Could not fetch blocked IPs from service.');
    } finally {
      setFirewallLoading(false);
    }
  };

  useEffect(() => {
    Promise.resolve().then(() => {
      if (activeTab === 'models') {
        fetchModels();
      } else if (activeTab === 'firewall') {
        fetchBlockedIPs();
      }
    });
  }, [activeTab]);

  const handleActivateModel = async (id) => {
    if (!confirm('Are you sure you want to switch the active machine learning model for live network classification?')) return;
    
    try {
      const updated = await modelsService.activateModel(id);
      setModels(prev => prev.map(m => ({
        ...m,
        is_active: m.id === updated.id
      })));
      setActiveModel(updated);
    } catch (err) {
      alert('Failed to switch model: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleBlockIP = async (e) => {
    e.preventDefault();
    if (!newIP || !blockReason) {
      setFirewallError('IP Address and Block Reason are required.');
      return;
    }
    
    // Quick regex validation for IPv4
    const ipv4Regex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/;
    if (!ipv4Regex.test(newIP)) {
      setFirewallError('Please provide a valid IPv4 address.');
      return;
    }

    setSubmittingBlock(true);
    setFirewallError('');
    try {
      await alertsService.blockIP(newIP, blockReason);
      setNewIP('');
      setBlockReason('');
      fetchBlockedIPs();
    } catch (err) {
      setFirewallError(err.response?.data?.detail || 'Failed to block the IP address.');
    } finally {
      setSubmittingBlock(false);
    }
  };

  const handleUnblockIP = async (id, ipAddress) => {
    if (!confirm(`Are you sure you want to remove the firewall rule blocking IP: ${ipAddress}?`)) return;

    try {
      await alertsService.unblockIP(id);
      setBlockedIPs(prev => prev.filter(item => item.id !== id));
    } catch (err) {
      alert('Failed to unblock IP: ' + (err.response?.data?.detail || err.message));
    }
  };

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '30px' }}>
      
      {/* Tab Navigation header */}
      <div style={{
        display: 'flex',
        borderBottom: '1px solid var(--border-color)',
        gap: '4px',
        paddingBottom: '0'
      }}>
        <button 
          onClick={() => setActiveTab('sniffer')}
          style={{
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'sniffer' ? '2px solid var(--primary)' : '2px solid transparent',
            color: activeTab === 'sniffer' ? 'var(--text-primary)' : 'var(--text-secondary)',
            padding: '12px 24px',
            cursor: 'pointer',
            fontSize: '0.95rem',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            transition: 'var(--transition)'
          }}
        >
          <Radio size={16} />
          Sniffer Daemon Config
        </button>

        <button 
          onClick={() => setActiveTab('models')}
          style={{
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'models' ? '2px solid var(--primary)' : '2px solid transparent',
            color: activeTab === 'models' ? 'var(--text-primary)' : 'var(--text-secondary)',
            padding: '12px 24px',
            cursor: 'pointer',
            fontSize: '0.95rem',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            transition: 'var(--transition)'
          }}
        >
          <Binary size={16} />
          ML Classifiers
        </button>

        <button 
          onClick={() => setActiveTab('firewall')}
          style={{
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'firewall' ? '2px solid var(--primary)' : '2px solid transparent',
            color: activeTab === 'firewall' ? 'var(--text-primary)' : 'var(--text-secondary)',
            padding: '12px 24px',
            cursor: 'pointer',
            fontSize: '0.95rem',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            transition: 'var(--transition)'
          }}
        >
          <Shield size={16} />
          Firewall Rules
        </button>
      </div>

      {/* -------------------- TAB CONTENT: SNIFFER CONFIG -------------------- */}
      {activeTab === 'sniffer' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          
          <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h3 style={{ fontSize: '1.25rem', fontWeight: 800 }}>Scapy Ingestion Ingress Settings</h3>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Configure NIC interface bindings and promiscuous filters.</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Capture Engine Status:</span>
                <button
                  onClick={() => setSnifferActive(!snifferActive)}
                  style={{
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer',
                    color: snifferActive ? 'var(--color-benign)' : 'var(--text-muted)',
                    display: 'flex',
                    alignItems: 'center'
                  }}
                  title={snifferActive ? 'Click to pause capture' : 'Click to start capture'}
                >
                  {snifferActive ? <ToggleRight size={40} /> : <ToggleLeft size={40} />}
                </button>
              </div>
            </div>

            <div style={{ width: '100%', height: '1px', backgroundColor: 'var(--border-color)' }}></div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
              {/* Left Form */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
                    MONITORED INTERFACE CARD
                  </label>
                  <select 
                    value={selectedInterface} 
                    onChange={(e) => setSelectedInterface(e.target.value)}
                    style={{
                      width: '100%',
                      backgroundColor: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '8px',
                      color: 'var(--text-primary)',
                      padding: '12px',
                      fontSize: '0.85rem',
                      outline: 'none'
                    }}
                  >
                    <option value="Ethernet0 (Realtek PCIe GbE)">Ethernet0 (Realtek PCIe GbE)</option>
                    <option value="Wi-Fi (Intel Wi-Fi 6E AX211)">Wi-Fi (Intel Wi-Fi 6E AX211)</option>
                    <option value="Loopback Pseudo-Interface 1">Loopback Pseudo-Interface 1</option>
                    <option value="All interfaces (Non-promiscuous)">All interfaces (Non-promiscuous)</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
                    BPF PACKET FILTER QUERY
                  </label>
                  <input 
                    type="text" 
                    value={filterQuery}
                    onChange={(e) => setFilterQuery(e.target.value)}
                    style={{
                      width: '100%',
                      backgroundColor: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '8px',
                      color: 'var(--text-primary)',
                      padding: '12px',
                      fontSize: '0.85rem',
                      fontFamily: 'var(--font-mono)',
                      outline: 'none'
                    }}
                  />
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '4px', display: 'block' }}>
                    Berkeley Packet Filter (BPF) syntax limits sniffer system load by dropping packets at kernel level.
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '8px' }}>
                  <input 
                    type="checkbox" 
                    id="promiscuous" 
                    checked={promiscuousMode}
                    onChange={(e) => setPromiscuousMode(e.target.checked)}
                    style={{
                      width: '16px',
                      height: '16px',
                      accentColor: 'var(--primary)',
                      cursor: 'pointer'
                    }}
                  />
                  <label htmlFor="promiscuous" style={{ fontSize: '0.85rem', color: 'var(--text-primary)', cursor: 'pointer', userSelect: 'none' }}>
                    Enable Promiscuous Mode (Capture all subnet segments traffic)
                  </label>
                </div>
              </div>

              {/* Right explanation and active diagnostics */}
              <div style={{
                backgroundColor: 'rgba(255,255,255,0.02)',
                border: '1px solid var(--border-color)',
                borderRadius: '8px',
                padding: '16px',
                display: 'flex',
                flexDirection: 'column',
                gap: '12px'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--primary)', fontSize: '0.85rem', fontWeight: 700 }}>
                  <Sliders size={16} />
                  <span>LIVE DAEMON METRICS</span>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginTop: '4px' }}>
                  <div style={{ backgroundColor: 'var(--bg-primary)', padding: '10px', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                    <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', display: 'block' }}>THREAD POOL</span>
                    <span style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }} className="text-mono">4 Workers Active</span>
                  </div>
                  <div style={{ backgroundColor: 'var(--bg-primary)', padding: '10px', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                    <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', display: 'block' }}>AVG CLASSIFY TIME</span>
                    <span style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--color-benign)' }} className="text-mono">11.4 ms</span>
                  </div>
                  <div style={{ backgroundColor: 'var(--bg-primary)', padding: '10px', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                    <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', display: 'block' }}>RAW PKT QUEUE</span>
                    <span style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }} className="text-mono">0 / 5000 pkts</span>
                  </div>
                  <div style={{ backgroundColor: 'var(--bg-primary)', padding: '10px', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                    <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', display: 'block' }}>LOG INGEST ROUTE</span>
                    <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--primary)' }} className="text-mono">/logs/</span>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', marginTop: '8px', color: 'var(--text-secondary)' }}>
                  <Network size={16} style={{ flexShrink: 0, marginTop: '2px', color: 'var(--primary)' }} />
                  <p style={{ fontSize: '0.75rem', lineHeight: '1.4' }}>
                    Sniffer simulator script intercepts frames, extracts header features (source, destination, protocol, ports, length) and relays arrays directly to the prediction core.
                  </p>
                </div>
              </div>
            </div>

            <div style={{ width: '100%', height: '1px', backgroundColor: 'var(--border-color)' }}></div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button 
                onClick={() => alert('Ingress configuration applied to active capturing service successfully.')}
                className="cyan-glow"
                style={{
                  backgroundColor: 'var(--primary)',
                  color: '#0b0f19',
                  border: 'none',
                  borderRadius: '6px',
                  padding: '10px 20px',
                  fontSize: '0.85rem',
                  fontWeight: 700,
                  cursor: 'pointer',
                  transition: 'var(--transition)'
                }}
              >
                Apply Ingress Config
              </button>
            </div>
          </div>
        </div>
      )}

      {/* -------------------- TAB CONTENT: ML CLASSIFIERS -------------------- */}
      {activeTab === 'models' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          
          {/* Active model spotlight */}
          {activeModel ? (
            <div className="glass-panel cyan-glow" style={{
              display: 'grid',
              gridTemplateColumns: '8fr 4fr',
              gap: '30px',
              alignItems: 'center',
              background: 'linear-gradient(135deg, rgba(17, 24, 39, 0.9) 0%, rgba(6, 182, 212, 0.04) 100%)'
            }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--primary)', marginBottom: '12px' }}>
                  <Sparkles size={16} />
                  <span style={{ fontSize: '0.75rem', fontWeight: 700, letterSpacing: '1px', textTransform: 'uppercase' }}>Active Classifier Live</span>
                </div>
                <h3 style={{ fontSize: '1.5rem', fontWeight: 800, marginBottom: '6px' }}>{activeModel.model_name}</h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '20px' }}>
                  Currently processing Scapy network packet flow feature arrays and predicting cyber threats in real-time.
                </p>
                <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap' }}>
                  <div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block' }}>VERSION</span>
                    <span style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '0.95rem' }} className="text-mono">{activeModel.version}</span>
                  </div>
                  <div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block' }}>DEPLOYED ON</span>
                    <span style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '0.95rem' }} className="text-mono">
                      {new Date(activeModel.deployed_at).toLocaleDateString()} {new Date(activeModel.deployed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                  <div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block' }}>SERIALIZED PATH</span>
                    <span style={{ fontWeight: 600, color: 'var(--text-secondary)', fontSize: '0.8rem' }} className="text-mono">{activeModel.filepath}</span>
                  </div>
                </div>
              </div>

              {/* Model metrics widgets */}
              <div style={{
                display: 'flex',
                gap: '16px',
                backgroundColor: 'var(--bg-primary)',
                padding: '20px',
                borderRadius: 'var(--radius)',
                border: '1px solid var(--border-color)',
                justifyContent: 'space-around'
              }}>
                <div style={{ textAlign: 'center' }}>
                  <Award size={20} color="var(--primary)" style={{ marginBottom: '6px' }} />
                  <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', display: 'block' }}>ACCURACY</span>
                  <span style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--primary)' }} className="text-mono">
                    {(activeModel.accuracy * 100).toFixed(1)}%
                  </span>
                </div>
                <div style={{ width: '1px', backgroundColor: 'var(--border-color)' }}></div>
                <div style={{ textAlign: 'center' }}>
                  <Cpu size={20} color="var(--color-benign)" style={{ marginBottom: '6px' }} />
                  <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', display: 'block' }}>WEIGHTED F1</span>
                  <span style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--color-benign)' }} className="text-mono">
                    {(activeModel.f1_score * 100).toFixed(1)}%
                  </span>
                </div>
              </div>
            </div>
          ) : (
            <div className="glass-panel" style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
              No machine learning model is currently marked as active in settings.
            </div>
          )}

          {/* Model registry list */}
          <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h4 style={{ fontSize: '1.1rem', fontWeight: 800 }}>Model Version Registries</h4>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Toggle active model weight assets on the fly.</span>
              </div>
              <button 
                onClick={fetchModels}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  fontSize: '0.8rem'
                }}
              >
                <RefreshCw size={14} /> Refresh Models
              </button>
            </div>

            <div style={{ overflowX: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
                <thead>
                  <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-color)' }}>
                    <th style={{ padding: '14px 16px', color: 'var(--text-muted)' }}>VERSION</th>
                    <th style={{ padding: '14px 16px', color: 'var(--text-muted)' }}>MODEL TYPE NAME</th>
                    <th style={{ padding: '14px 16px', color: 'var(--text-muted)' }}>TEST ACCURACY</th>
                    <th style={{ padding: '14px 16px', color: 'var(--text-muted)' }}>F1-SCORE</th>
                    <th style={{ padding: '14px 16px', color: 'var(--text-muted)' }}>STATUS</th>
                    <th style={{ padding: '14px 16px', color: 'var(--text-muted)', textAlign: 'right' }}>TOGGLE LIVE</th>
                  </tr>
                </thead>
                <tbody>
                  {!modelsLoading && models.length > 0 ? models.map((model) => (
                    <tr 
                      key={model.id} 
                      style={{ 
                        borderBottom: '1px solid var(--border-color)', 
                        backgroundColor: model.is_active ? 'rgba(6, 182, 212, 0.01)' : 'transparent' 
                      }}
                    >
                      <td style={{ padding: '14px 16px', fontWeight: 600 }} className="text-mono">{model.version}</td>
                      <td style={{ padding: '14px 16px', fontWeight: 700 }}>{model.model_name}</td>
                      <td style={{ padding: '14px 16px' }} className="text-mono">{(model.accuracy * 100).toFixed(2)}%</td>
                      <td style={{ padding: '14px 16px' }} className="text-mono">{(model.f1_score * 100).toFixed(2)}%</td>
                      <td style={{ padding: '14px 16px' }}>
                        {model.is_active ? (
                          <span className="badge badge-benign" style={{ gap: '4px' }}>
                            <CheckCircle size={12} />
                            ACTIVE
                          </span>
                        ) : (
                          <span className="badge" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                            STANDBY
                          </span>
                        )}
                      </td>
                      <td style={{ padding: '14px 16px', textAlign: 'right' }}>
                        {!model.is_active ? (
                          <button 
                            onClick={() => handleActivateModel(model.id)}
                            style={{
                              background: 'none',
                              border: 'none',
                              color: 'var(--text-secondary)',
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              padding: '4px',
                              transition: 'var(--transition)'
                            }}
                            title="Click to activate model"
                          >
                            <ToggleLeft size={28} />
                          </button>
                        ) : (
                          <span style={{ color: 'var(--primary)', padding: '4px', display: 'inline-flex', alignItems: 'center' }}>
                            <ToggleRight size={28} />
                          </span>
                        )}
                      </td>
                    </tr>
                  )) : (
                    <tr>
                      <td colSpan="6" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                        {modelsLoading ? 'Querying ML model registry...' : 'No models registered in system databases.'}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* -------------------- TAB CONTENT: FIREWALL RULES -------------------- */}
      {activeTab === 'firewall' && (
        <div style={{ display: 'grid', gridTemplateColumns: '4fr 8fr', gap: '30px', alignItems: 'start' }}>
          
          {/* Block IP Form */}
          <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div>
              <h3 style={{ fontSize: '1.15rem', fontWeight: 800 }}>Ban Network Hosts</h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Add iptables/firewall drop rules for malicious IP endpoints.</span>
            </div>

            {firewallError && (
              <div style={{ 
                backgroundColor: 'rgba(239, 68, 68, 0.1)', 
                border: '1px solid rgba(239, 68, 68, 0.2)', 
                color: 'var(--color-critical)',
                padding: '12px',
                borderRadius: '6px',
                fontSize: '0.8rem',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}>
                <AlertTriangle size={14} style={{ flexShrink: 0 }} />
                <span>{firewallError}</span>
              </div>
            )}

            <form onSubmit={handleBlockIP} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  TARGET IP ADDRESS
                </label>
                <input 
                  type="text" 
                  value={newIP}
                  onChange={(e) => setNewIP(e.target.value)}
                  placeholder="e.g. 192.168.1.150"
                  style={{
                    width: '100%',
                    backgroundColor: 'var(--bg-tertiary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '8px',
                    color: 'var(--text-primary)',
                    padding: '10px 12px',
                    fontSize: '0.85rem',
                    fontFamily: 'var(--font-mono)',
                    outline: 'none'
                  }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  REASON / ATTACK EVENT
                </label>
                <input 
                  type="text" 
                  value={blockReason}
                  onChange={(e) => setBlockReason(e.target.value)}
                  placeholder="e.g. Repetitive DDoS Attack Inbound"
                  style={{
                    width: '100%',
                    backgroundColor: 'var(--bg-tertiary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '8px',
                    color: 'var(--text-primary)',
                    padding: '10px 12px',
                    fontSize: '0.85rem',
                    outline: 'none'
                  }}
                />
              </div>

              <button 
                type="submit"
                disabled={submittingBlock}
                className="critical-glow"
                style={{
                  width: '100%',
                  backgroundColor: 'rgba(239, 68, 68, 0.1)',
                  color: 'var(--color-critical)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  borderRadius: '8px',
                  padding: '12px',
                  fontSize: '0.85rem',
                  fontWeight: 700,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                  transition: 'var(--transition)'
                }}
              >
                <Plus size={16} />
                {submittingBlock ? 'Injecting rule...' : 'Enforce IP Ban'}
              </button>
            </form>
          </div>

          {/* Blocked IPs Table */}
          <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h3 style={{ fontSize: '1.15rem', fontWeight: 800 }}>Active Firewall Banlist</h3>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Lists of drops currently loaded in NIDS packet filter.</span>
              </div>
              <button 
                onClick={fetchBlockedIPs}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  fontSize: '0.8rem'
                }}
              >
                <RefreshCw size={14} /> Refresh Banlist
              </button>
            </div>

            <div style={{ overflowX: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
                <thead>
                  <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-color)' }}>
                    <th style={{ padding: '12px 14px', color: 'var(--text-muted)' }}>IP ADDRESS</th>
                    <th style={{ padding: '12px 14px', color: 'var(--text-muted)' }}>BLOCKED REASON</th>
                    <th style={{ padding: '12px 14px', color: 'var(--text-muted)' }}>BLOCKED AT</th>
                    <th style={{ padding: '12px 14px', color: 'var(--text-muted)' }}>STATUS</th>
                    <th style={{ padding: '12px 14px', color: 'var(--text-muted)', textAlign: 'right' }}>UNBAN</th>
                  </tr>
                </thead>
                <tbody>
                  {!firewallLoading && blockedIPs.length > 0 ? blockedIPs.map((item) => (
                    <tr key={item.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '12px 14px', fontWeight: 700 }} className="text-mono">{item.ip_address}</td>
                      <td style={{ padding: '12px 14px', color: 'var(--text-secondary)' }}>{item.blocked_reason}</td>
                      <td style={{ padding: '12px 14px', color: 'var(--text-muted)' }} className="text-mono">
                        {new Date(item.blocked_at).toLocaleDateString()} {new Date(item.blocked_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <span className="badge badge-critical">
                          ACTIVE
                        </span>
                      </td>
                      <td style={{ padding: '12px 14px', textAlign: 'right' }}>
                        <button 
                          onClick={() => handleUnblockIP(item.id, item.ip_address)}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: 'var(--text-muted)',
                            cursor: 'pointer',
                            padding: '4px',
                            display: 'inline-flex',
                            alignItems: 'center',
                            transition: 'var(--transition)'
                          }}
                          onMouseEnter={(e) => e.currentTarget.style.color = 'var(--color-critical)'}
                          onMouseLeave={(e) => e.currentTarget.style.color = 'var(--text-muted)'}
                          title="Remove block rule"
                        >
                          <Trash2 size={16} />
                        </button>
                      </td>
                    </tr>
                  )) : (
                    <tr>
                      <td colSpan="5" style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
                        {firewallLoading ? 'Loading active firewall rules...' : 'No IP addresses are currently blocked by firewall.'}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Settings;
