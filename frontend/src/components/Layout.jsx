import { useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { 
  ShieldAlert, 
  Activity, 
  Settings as SettingsIcon, 
  LogOut, 
  User as UserIcon, 
  Radio,
  BarChart3,
  FileText,
  Wifi,
  WifiOff,
  Monitor,
  Lock
} from 'lucide-react';
import { authService } from '../services/api';
import { liveSocket } from '../services/websocket';

const Layout = ({ children }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const [user, setUser] = useState(null);
  const [wsConnected, setWsConnected] = useState(false);

  useEffect(() => {
    // Load operator profile
    authService.getMe()
      .then(setUser)
      .catch(() => {
        authService.logout();
        navigate('/login');
      });

    // Start WebSocket
    liveSocket.connect((connected) => {
      setWsConnected(connected);
    });

    return () => {
      liveSocket.disconnect();
    };
  }, [navigate]);

  const handleLogout = () => {
    authService.logout();
    liveSocket.disconnect();
    navigate('/login');
  };

  const navItems = [
    { name: 'Dashboard', path: '/', icon: Activity },
    { name: 'Real-Time Monitor', path: '/realtime', icon: Monitor },
    { name: 'Live Traffic', path: '/traffic', icon: Radio },
    { name: 'Alerts Logs', path: '/alerts', icon: ShieldAlert },
    { name: 'Attack Analytics', path: '/analytics', icon: BarChart3 },
    { name: 'System Logs', path: '/system-logs', icon: FileText }
  ];

  if (user && user.role === 'admin') {
    navItems.push({ name: 'Admin Console', path: '/admin', icon: Lock });
  }

  navItems.push({ name: 'System Settings', path: '/settings', icon: SettingsIcon });

  return (
    <div style={{ display: 'flex', minHeight: '100vh', backgroundColor: 'var(--bg-primary)' }}>
      {/* Sidebar */}
      <aside style={{
        width: '260px',
        backgroundColor: 'var(--bg-secondary)',
        borderRight: '1px solid var(--border-color)',
        padding: '24px 16px',
        display: 'flex',
        flexDirection: 'column',
        position: 'fixed',
        height: '100vh',
        zIndex: 10
      }}>
        {/* Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '40px', padding: '0 8px' }}>
          <div style={{
            backgroundColor: 'var(--primary)',
            padding: '8px',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 10px rgba(6, 182, 212, 0.4)'
          }}>
            <ShieldAlert size={24} color="#0b0f19" />
          </div>
          <div>
            <h1 style={{ fontSize: '1.1rem', fontWeight: 800, color: 'var(--text-primary)', tracking: 'wide' }}>AETHER NIDS</h1>
            <span style={{ fontSize: '0.65rem', color: 'var(--primary)', fontWeight: 600, letterSpacing: '1px' }}>AI NETWORK GUARD</span>
          </div>
        </div>

        {/* Navigation */}
        <nav style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {navItems.map((item) => {
            const isActive = location.pathname === item.path;
            const Icon = item.icon;
            return (
              <button
                key={item.path}
                onClick={() => navigate(item.path)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  padding: '12px 16px',
                  borderRadius: 'var(--radius)',
                  border: 'none',
                  backgroundColor: isActive ? 'rgba(6, 182, 212, 0.1)' : 'transparent',
                  color: isActive ? 'var(--primary)' : 'var(--text-secondary)',
                  cursor: 'pointer',
                  textAlign: 'left',
                  fontSize: '0.9rem',
                  fontWeight: isActive ? 600 : 500,
                  transition: 'var(--transition)',
                  borderLeft: isActive ? '3px solid var(--primary)' : '3px solid transparent',
                  borderTopLeftRadius: '0px',
                  borderBottomLeftRadius: '0px'
                }}
              >
                <Icon size={18} />
                {item.name}
              </button>
            );
          })}
        </nav>

        {/* User profile & Logout */}
        <div style={{
          borderTop: '1px solid var(--border-color)',
          paddingTop: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px'
        }}>
          {user && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '0 8px' }}>
              <div style={{
                width: '36px',
                height: '36px',
                borderRadius: '50%',
                backgroundColor: 'var(--bg-tertiary)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                border: '1px solid var(--border-color)'
              }}>
                <UserIcon size={18} color="var(--text-secondary)" />
              </div>
              <div style={{ overflow: 'hidden' }}>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {user.username}
                </h4>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'capitalize' }}>
                  {user.role}
                </span>
              </div>
            </div>
          )}

          <button
            onClick={handleLogout}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              padding: '12px 16px',
              borderRadius: 'var(--radius)',
              border: 'none',
              backgroundColor: 'rgba(239, 68, 68, 0.05)',
              color: 'var(--color-critical)',
              cursor: 'pointer',
              fontSize: '0.9rem',
              fontWeight: 500,
              transition: 'var(--transition)',
              width: '100%'
            }}
          >
            <LogOut size={18} />
            Logout
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div style={{ flex: 1, marginLeft: '260px', display: 'flex', flexDirection: 'column' }}>
        {/* Topbar Header */}
        <header style={{
          height: '70px',
          backgroundColor: 'var(--bg-secondary)',
          borderBottom: '1px solid var(--border-color)',
          padding: '0 32px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          position: 'sticky',
          top: 0,
          zIndex: 9
        }}>
          <div>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 500 }}>CURRENT AREA</span>
            <h2 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {navItems.find(item => item.path === location.pathname)?.name || 'NIDS Console'}
            </h2>
          </div>

          {/* Status indicators */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
            {/* Live Socket Status */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.8rem', fontWeight: 500 }}>
              {wsConnected ? (
                <>
                  <Wifi size={16} color="var(--color-benign)" />
                  <span style={{ color: 'var(--color-benign)' }}>Live Stream Online</span>
                </>
              ) : (
                <>
                  <WifiOff size={16} color="var(--color-critical)" />
                  <span style={{ color: 'var(--color-critical)' }}>Live Stream Offline</span>
                </>
              )}
            </div>

            {/* Daemon Sniffer indicator */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              backgroundColor: 'rgba(16, 185, 129, 0.05)',
              padding: '6px 12px',
              borderRadius: '9999px',
              border: '1px solid rgba(16, 185, 129, 0.15)',
              fontSize: '0.8rem',
              fontWeight: 600
            }}>
              <span style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                backgroundColor: 'var(--color-benign)'
              }} className="pulse-dot"></span>
              <Radio size={14} color="var(--color-benign)" />
              <span style={{ color: 'var(--color-benign)' }}>SNIFFER: ACTIVE</span>
            </div>
          </div>
        </header>

        {/* Routed Components Content */}
        <main style={{ padding: '32px', flex: 1, backgroundColor: 'var(--bg-primary)' }}>
          {children}
        </main>
      </div>
    </div>
  );
};

export default Layout;
