import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || (typeof window !== 'undefined'
  ? (window.location.port === '3000' || window.location.port === '5173'
      ? `http://${window.location.hostname}:8000/api/v1`
      : `${window.location.origin}/api/v1`)
  : 'http://localhost:8000/api/v1');

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to attach JWT token
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor for session expiry redirect
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('token');
      // If we are not on the login page, reload to trigger auth state reset
      if (!window.location.pathname.endsWith('/login')) {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

export const authService = {
  login: async (username, password) => {
    // FastAPI expects form data for token endpoint
    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('password', password);
    
    const response = await axios.post(`${API_BASE_URL}/auth/token`, formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    
    if (response.data.access_token) {
      localStorage.setItem('token', response.data.access_token);
    }
    return response.data;
  },
  register: async (username, email, password, role = 'operator') => {
    const response = await apiClient.post('/auth/register', { username, email, password, role });
    return response.data;
  },
  getMe: async () => {
    const response = await apiClient.get('/auth/me');
    return response.data;
  },
  logout: () => {
    localStorage.removeItem('token');
  },
  isAuthenticated: () => {
    return !!localStorage.getItem('token');
  }
};

export const logsService = {
  getLogs: async (skip = 0, limit = 50, search = '') => {
    const response = await apiClient.get('/logs/', {
      params: { skip, limit, search }
    });
    return response.data;
  },
  getLog: async (id) => {
    const response = await apiClient.get(`/logs/${id}`);
    return response.data;
  },
  getSystemLogs: async (skip = 0, limit = 100) => {
    const response = await apiClient.get('/logs/system/logs', {
      params: { skip, limit }
    });
    return response.data;
  }
};

export const alertsService = {
  getAlerts: async (statusFilter = '', severityFilter = '', skip = 0, limit = 50) => {
    const response = await apiClient.get('/alerts/', {
      params: {
        status_filter: statusFilter || undefined,
        severity_filter: severityFilter || undefined,
        skip,
        limit
      }
    });
    return response.data;
  },
  updateAlert: async (id, status, notes) => {
    const response = await apiClient.patch(`/alerts/${id}`, { status, notes });
    return response.data;
  },
  deleteAlert: async (id) => {
    const response = await apiClient.delete(`/alerts/${id}`);
    return response.data;
  },
  getBlockedIPs: async () => {
    const response = await apiClient.get('/alerts/blocked-ips');
    return response.data;
  },
  blockIP: async (ipAddress, blockedReason) => {
    const response = await apiClient.post('/alerts/blocked-ips', { ip_address: ipAddress, blocked_reason: blockedReason });
    return response.data;
  },
  unblockIP: async (id) => {
    const response = await apiClient.delete(`/alerts/blocked-ips/${id}`);
    return response.data;
  }
};

export const modelsService = {
  getModels: async () => {
    const response = await apiClient.get('/models/');
    return response.data;
  },
  activateModel: async (id) => {
    const response = await apiClient.post(`/models/${id}/activate`);
    return response.data;
  }
};

export const dashboardService = {
  getSummary: async () => {
    const response = await apiClient.get('/dashboard/summary');
    return response.data;
  }
};

export const usersService = {
  getUsers: async () => {
    const response = await apiClient.get('/users/');
    return response.data;
  },
  updateUserRole: async (userId, role) => {
    const response = await apiClient.put(`/users/${userId}/role`, { role });
    return response.data;
  },
  deleteUser: async (userId) => {
    const response = await apiClient.delete(`/users/${userId}`);
    return response.data;
  }
};

export const systemService = {
  getHealth: async () => {
    const response = await apiClient.get('/system/health');
    return response.data;
  }
};

export const reportsService = {
  exportReport: async (type, format, startDate, endDate) => {
    const response = await apiClient.get('/reports/export', {
      params: {
        report_type: type,
        export_format: format,
        start_date: startDate || undefined,
        end_date: endDate || undefined
      },
      responseType: 'blob'
    });
    return response.data;
  }
};

