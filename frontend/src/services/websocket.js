export class LiveSocketClient {
  constructor() {
    this.socket = null;
    this.listeners = new Map();
    this.reconnectTimer = null;
    this.isConnected = false;
  }

  connect(onStatusChange = null) {
    const token = localStorage.getItem('token');
    if (!token) {
      console.warn('[WS Client] Missing token, cannot connect WebSocket.');
      return;
    }

    if (this.socket && (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING)) {
      return;
    }
    // Connect via token query param
    const isDev = typeof window !== 'undefined' && (window.location.port === '3000' || window.location.port === '5173');
    const wsProtocol = typeof window !== 'undefined' && window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsHost = isDev ? `${window.location.hostname}:8000` : (typeof window !== 'undefined' ? window.location.host : 'localhost:8000');
    const wsUrl = `${wsProtocol}//${wsHost}/api/v1/ws/live?token=${encodeURIComponent(token)}`;
    console.log('[WS Client] Connecting to security stream...');
    
    this.socket = new WebSocket(wsUrl);

    this.socket.onopen = () => {
      console.log('[WS Client] Connection established.');
      this.isConnected = true;
      if (this.reconnectTimer) {
        clearTimeout(this.reconnectTimer);
        this.reconnectTimer = null;
      }
      if (onStatusChange) onStatusChange(true);
    };

    this.socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        const eventName = payload.event;
        
        if (this.listeners.has(eventName)) {
          this.listeners.get(eventName).forEach((callback) => {
            callback(payload.data, payload.timestamp);
          });
        }
        
        // Wildcard listeners
        if (this.listeners.has('*')) {
          this.listeners.get('*').forEach((callback) => {
            callback(payload);
          });
        }
      } catch (err) {
        console.error('[WS Client] Parse error: ', err);
      }
    };

    this.socket.onclose = (e) => {
      console.log('[WS Client] Connection closed: ', e.reason);
      this.isConnected = false;
      if (onStatusChange) onStatusChange(false);
      
      // Auto reconnect after 3 seconds
      if (!this.reconnectTimer) {
        this.reconnectTimer = setTimeout(() => {
          this.reconnectTimer = null;
          this.connect(onStatusChange);
        }, 3000);
      }
    };

    this.socket.onerror = (err) => {
      console.error('[WS Client] Socket error: ', err);
      this.socket.close();
    };
  }

  disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.isConnected = false;
  }

  addEventListener(eventName, callback) {
    if (!this.listeners.has(eventName)) {
      this.listeners.set(eventName, []);
    }
    this.listeners.get(eventName).push(callback);
    return () => this.removeEventListener(eventName, callback);
  }

  removeEventListener(eventName, callback) {
    if (this.listeners.has(eventName)) {
      const list = this.listeners.get(eventName);
      const index = list.indexOf(callback);
      if (index !== -1) {
        list.splice(index, 1);
      }
    }
  }
}

// Singleton global client instance
export const liveSocket = new LiveSocketClient();
