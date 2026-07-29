class ApiClient {
  constructor(baseUrl = '/api/v1') {
    this.baseUrl = baseUrl;
    this.wsBase = this._getWsBase();
  }

  _getWsBase() {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    return `${proto}//${host}/ws`;
  }

  _getToken() {
    return localStorage.getItem('nmapai_token');
  }

  _setToken(token) {
    if (token) {
      localStorage.setItem('nmapai_token', token);
    } else {
      localStorage.removeItem('nmapai_token');
    }
  }

  async _request(method, path, data = null) {
    const url = `${this.baseUrl}${path}`;
    const headers = { 'Content-Type': 'application/json' };
    const token = this._getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const opts = {
      method,
      headers,
    };

    if (data !== null && data !== undefined) {
      opts.body = JSON.stringify(data);
    }

    try {
      const res = await fetch(url, opts);

      if (res.status === 401) {
        this._setToken(null);
        if (window.app && window.app.showLogin) {
          window.app.showLogin();
        }
        throw new ApiError('Authentication required. Please log in.', 401);
      }

      if (res.status === 204) {
        return null;
      }

      const contentType = res.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        const body = await res.json();
        if (!res.ok) {
          throw new ApiError(body.detail || body.message || `Request failed with status ${res.status}`, res.status, body);
        }
        return body;
      } else {
        const text = await res.text();
        if (!res.ok) {
          throw new ApiError(text || `Request failed with status ${res.status}`, res.status);
        }
        return text;
      }
    } catch (err) {
      if (err instanceof ApiError) throw err;
      throw new ApiError(err.message || 'Network error. Please check your connection.', 0);
    }
  }

  // Auth
  async login(username, password) {
    const url = `${this.baseUrl}/auth/login`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new ApiError(body.detail || 'Login failed', res.status);
    }

    const data = await res.json();
    this._setToken(data.access_token);
    return data;
  }

  async register(username, email, password, role = 'viewer') {
    return this._request('POST', '/auth/register', { username, email, password, role });
  }

  async getMe() {
    return this._request('GET', '/auth/me');
  }

  // Targets
  async getTargets() {
    return this._request('GET', '/targets');
  }

  async createTarget(name, value, type, project, tags) {
    return this._request('POST', '/targets', {
      name,
      target_value: value,
      target_type: type,
      project: project || null,
      tags: tags || [],
    });
  }

  async deleteTarget(id) {
    return this._request('DELETE', `/targets/${id}`);
  }

  async validateTarget(value) {
    return this._request('POST', '/targets/validate', { target_value: value });
  }

  // Scan Profiles
  async getScanProfiles() {
    return this._request('GET', '/scan-profiles');
  }

  async createScanProfile(data) {
    return this._request('POST', '/scan-profiles', data);
  }

  // Scans
  async launchScan(name, targetId, profileId) {
    return this._request('POST', '/scans', {
      name,
      target_id: targetId,
      profile_id: profileId,
    });
  }

  async getScans(status = null) {
    let path = '/scans';
    if (status) {
      path += `?status=${encodeURIComponent(status)}`;
    }
    return this._request('GET', path);
  }

  async getScanStatus(id) {
    return this._request('GET', `/scans/${id}/status`);
  }

  async getScanResults(id) {
    return this._request('GET', `/scans/${id}/results`);
  }

  async getScanRaw(id) {
    return this._request('GET', `/scans/${id}/raw`);
  }

  async cancelScan(id) {
    return this._request('POST', `/scans/${id}/cancel`);
  }

  async pauseScan(id) {
    return this._request('POST', `/scans/${id}/pause`);
  }

  async resumeScan(id) {
    return this._request('POST', `/scans/${id}/resume`);
  }

  // Hosts
  async getHosts(scanId) {
    return this._request('GET', `/scans/${scanId}/hosts`);
  }

  async getHostDetail(scanId, hostId) {
    return this._request('GET', `/scans/${scanId}/hosts/${hostId}`);
  }

  // Export
  async exportScan(id, format) {
    const url = `${this.baseUrl}/scans/export/${id}?format=${encodeURIComponent(format)}`;
    const token = this._getToken();
    const headers = {};
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const res = await fetch(url, { headers });
    if (!res.ok) {
      throw new ApiError('Export failed', res.status);
    }

    const blob = await res.blob();
    const ext = format === 'pdf' ? '.pdf' : format === 'csv' ? '.csv' : '.json';
    const filename = `scan-${id}${ext}`;
    const downloadUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(downloadUrl);
    return true;
  }

  // AI
  async getAIInsights(scanId) {
    return this._request('GET', `/ai/insights/${scanId}`);
  }

  async summarize(scanId) {
    return this._request('POST', `/ai/summarize/${scanId}`);
  }

  async riskScore(scanId) {
    return this._request('POST', `/ai/risk-score/${scanId}`);
  }

  async compare(scanId1, scanId2) {
    return this._request('POST', '/ai/compare', { scan_id_1: scanId1, scan_id_2: scanId2 });
  }

  async query(query, scanId) {
    return this._request('POST', '/ai/query', { query, scan_id: scanId });
  }

  async recommend(scanId) {
    return this._request('POST', `/ai/recommend/${scanId}`);
  }

  // Users
  async getUsers() {
    return this._request('GET', '/users');
  }

  async updateUserRole(id, role) {
    return this._request('PUT', `/users/${id}/role`, { role });
  }

  // WebSocket
  connectWebSocket(scanId, onMessage) {
    const token = this._getToken();
    const wsUrl = `${this.wsBase}/${scanId}?token=${encodeURIComponent(token || '')}`;
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      console.log(`WebSocket connected for scan ${scanId}`);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (onMessage) onMessage(data);
      } catch (e) {
        console.warn('WebSocket message parse error:', e);
      }
    };

    ws.onerror = (err) => {
      console.error('WebSocket error:', err);
    };

    ws.onclose = () => {
      console.log(`WebSocket disconnected for scan ${scanId}`);
    };

    return ws;
  }
}

class ApiError extends Error {
  constructor(message, status, body = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

window.api = new ApiClient();
