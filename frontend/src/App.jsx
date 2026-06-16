import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Login from './pages/Login';
import Overview from './pages/Overview';
import Alerts from './pages/Alerts';
import LiveTraffic from './pages/LiveTraffic';
import AttackAnalytics from './pages/AttackAnalytics';
import SystemLogs from './pages/SystemLogs';
import Settings from './pages/Settings';
import RealTimeDashboard from './pages/RealTimeDashboard';
import Admin from './pages/Admin';
import { authService } from './services/api';

// Route protector checks local storage JWT auth
const ProtectedRoute = ({ children }) => {
  const isAuthenticated = authService.isAuthenticated();
  return isAuthenticated ? <Layout>{children}</Layout> : <Navigate to="/login" replace />;
};

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Authentication Route */}
        <Route path="/login" element={<Login />} />

        {/* Protected Dashboard Console Routes */}
        <Route path="/" element={
          <ProtectedRoute>
            <Overview />
          </ProtectedRoute>
        } />

        <Route path="/realtime" element={
          <ProtectedRoute>
            <RealTimeDashboard />
          </ProtectedRoute>
        } />
        
        <Route path="/admin" element={
          <ProtectedRoute>
            <Admin />
          </ProtectedRoute>
        } />
        
        <Route path="/traffic" element={
          <ProtectedRoute>
            <LiveTraffic />
          </ProtectedRoute>
        } />

        <Route path="/alerts" element={
          <ProtectedRoute>
            <Alerts />
          </ProtectedRoute>
        } />

        <Route path="/analytics" element={
          <ProtectedRoute>
            <AttackAnalytics />
          </ProtectedRoute>
        } />

        <Route path="/system-logs" element={
          <ProtectedRoute>
            <SystemLogs />
          </ProtectedRoute>
        } />

        <Route path="/settings" element={
          <ProtectedRoute>
            <Settings />
          </ProtectedRoute>
        } />

        {/* Catch-all redirect */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
