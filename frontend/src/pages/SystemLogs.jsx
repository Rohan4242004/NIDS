import { useEffect, useState } from 'react';
import { 
  Search, 
  AlertOctagon, 
  Info, 
  AlertTriangle,
  RotateCw
} from 'lucide-react';
import { logsService } from '../services/api';

const SystemLogs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [levelFilter, setLevelFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  const fetchSystemLogs = async () => {
    setLoading(true);
    try {
      const data = await logsService.getSystemLogs(0, 150);
      setLogs(data);
    } catch (err) {
      console.error('Failed to load system audit logs: ', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    Promise.resolve().then(() => {
      fetchSystemLogs();
    });
  }, []);

  const filteredLogs = logs.filter(log => {
    const matchesLevel = levelFilter ? log.log_level.toUpperCase() === levelFilter.toUpperCase() : true;
    const matchesSearch = searchQuery ? (
      log.module_name.toLowerCase().includes(searchQuery.toLowerCase()) || 
      log.message.toLowerCase().includes(searchQuery.toLowerCase())
    ) : true;
    return matchesLevel && matchesSearch;
  });

  const getLogLevelIcon = (level) => {
    const lvl = level.toUpperCase();
    if (lvl === 'ERROR') return <AlertOctagon size={14} color="var(--color-critical)" />;
    if (lvl === 'WARNING') return <AlertTriangle size={14} color="var(--color-medium)" />;
    return <Info size={14} color="var(--color-benign)" />;
  };

  const getLogLevelStyle = (level) => {
    const lvl = level.toUpperCase();
    if (lvl === 'ERROR') return { backgroundColor: 'rgba(239, 68, 68, 0.1)', color: 'var(--color-critical)', border: '1px solid rgba(239, 68, 68, 0.2)' };
    if (lvl === 'WARNING') return { backgroundColor: 'rgba(245, 158, 11, 0.1)', color: 'var(--color-medium)', border: '1px solid rgba(245, 158, 11, 0.2)' };
    return { backgroundColor: 'rgba(16, 185, 129, 0.1)', color: 'var(--color-benign)', border: '1px solid rgba(16, 185, 129, 0.2)' };
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '30px' }}>
      
      {/* Header and refresh */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ fontSize: '1.4rem', fontWeight: 800 }}>System Audit Logs</h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Backend system warnings, SMTP transmissions, and ML engine operational metrics.</p>
        </div>
        <button 
          onClick={fetchSystemLogs}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            backgroundColor: 'var(--bg-secondary)',
            border: '1px solid var(--border-color)',
            padding: '8px 16px',
            borderRadius: '8px',
            color: 'var(--text-primary)',
            fontSize: '0.85rem',
            cursor: 'pointer',
            fontWeight: 600,
            transition: 'var(--transition)'
          }}
        >
          <RotateCw size={14} />
          Refresh Logs
        </button>
      </div>

      {/* Filters & search log */}
      <div className="glass-panel" style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: '20px',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        {/* Search bar */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          backgroundColor: 'var(--bg-primary)',
          border: '1px solid var(--border-color)',
          padding: '8px 16px',
          borderRadius: '8px',
          width: '320px'
        }}>
          <Search size={16} color="var(--text-muted)" />
          <input 
            type="text" 
            placeholder="Search module or message..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-primary)',
              fontSize: '0.85rem',
              outline: 'none',
              width: '100%'
            }}
          />
        </div>

        {/* Level filter dropdown */}
        <select
          value={levelFilter}
          onChange={(e) => setLevelFilter(e.target.value)}
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
          <option value="">All Severity Levels</option>
          <option value="INFO">Info</option>
          <option value="WARNING">Warning</option>
          <option value="ERROR">Error</option>
        </select>
      </div>

      {/* Logs Table */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div style={{ overflowX: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-color)' }}>
                <th style={{ padding: '12px 16px', color: 'var(--text-muted)', width: '180px' }}>TIMESTAMP</th>
                <th style={{ padding: '12px 16px', color: 'var(--text-muted)', width: '100px' }}>LEVEL</th>
                <th style={{ padding: '12px 16px', color: 'var(--text-muted)', width: '150px' }}>MODULE</th>
                <th style={{ padding: '12px 16px', color: 'var(--text-muted)' }}>MESSAGE LOG</th>
              </tr>
            </thead>
            <tbody>
              {!loading && filteredLogs.length > 0 ? filteredLogs.map((log) => (
                <tr key={log.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <td style={{ padding: '12px 16px', color: 'var(--text-secondary)' }} className="text-mono">
                    {new Date(log.created_at).toLocaleString()}
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                      ...getLogLevelStyle(log.log_level)
                    }}>
                      {getLogLevelIcon(log.log_level)}
                      {log.log_level}
                    </span>
                  </td>
                  <td style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--primary)' }}>
                    {log.module_name}
                  </td>
                  <td style={{ padding: '12px 16px', color: 'var(--text-primary)' }}>
                    {log.message}
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan="4" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    {loading ? 'Fetching system audit logs...' : 'No logs found matching your filter criteria.'}
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

export default SystemLogs;
