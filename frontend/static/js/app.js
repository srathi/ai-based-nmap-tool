class App {
  constructor() {
    this.api = window.api;
    this.currentView = 'dashboard';
    this.user = null;
    this.scans = [];
    this.targets = [];
    this.profiles = [];
    this.users = [];
    this.scanCache = {};
    this.ws = null;
    this.selectedScanId = null;
    this.comparisonScan1 = null;
    this.comparisonScan2 = null;
    this.insightScanId = null;
  }

  async init() {
    this._setupGlobalListeners();
    this._handleHashChange();

    if (this.api._getToken()) {
      try {
        this.user = await this.api.getMe();
        this._updateUserUI();
        this._loadView(this.currentView);
      } catch (e) {
        this.api._setToken(null);
        this.showLogin();
      }
    } else {
      this.showLogin();
    }
  }

  _setupGlobalListeners() {
    window.addEventListener('hashchange', () => this._handleHashChange());

    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const view = item.dataset.view;
        window.location.hash = view;
      });
    });
  }

  _handleHashChange() {
    const hash = window.location.hash.slice(1) || 'dashboard';
    this.currentView = hash;
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const activeNav = document.querySelector(`.nav-item[data-view="${hash}"]`);
    if (activeNav) activeNav.classList.add('active');

    if (this.api._getToken()) {
      this._loadView(hash);
    }
  }

  _updateUserUI() {
    if (this.user) {
      const nameEl = document.getElementById('userName');
      const roleEl = document.getElementById('userRole');
      if (nameEl) nameEl.textContent = this.user.username || this.user.email || 'User';
      if (roleEl) roleEl.textContent = (this.user.role || 'viewer').toUpperCase();
      document.getElementById('loginBtn').style.display = 'none';
      document.getElementById('logoutBtn').style.display = '';

      const avatar = document.querySelector('.user-avatar');
      if (avatar) {
        avatar.textContent = (this.user.username || 'U')[0].toUpperCase();
      }
    }
  }

  async _loadView(view) {
    const container = document.getElementById('view-container');
    container.innerHTML = '<div class="loading-screen"><div class="spinner"></div><p>Loading...</p></div>';

    try {
      switch (view) {
        case 'dashboard': await this.showDashboard(); break;
        case 'scans': await this.showScans(); break;
        case 'targets': await this.showTargets(); break;
        case 'profiles': await this.showProfiles(); break;
        case 'ai-insights': await this.showAIInsights(); break;
        case 'reports': await this.showReports(); break;
        case 'admin': await this.showAdmin(); break;
        default: await this.showDashboard(); break;
      }
    } catch (e) {
      if (e.status === 401) {
        this.showLogin();
      } else {
        this._renderError(container, e.message);
      }
    }
  }

  _renderError(container, message) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">&#9888;</div>
        <div class="empty-state-text">Error</div>
        <div class="empty-state-hint">${this._escapeHtml(message)}</div>
        <button class="btn btn-primary" onclick="app._loadView('${this.currentView}')">Retry</button>
      </div>`;
  }

  _show(html) {
    document.getElementById('view-container').innerHTML = html;
  }

  _escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // --- Login ---
  showLogin() {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    this._show(`
      <div class="login-container">
        <div class="login-card">
          <div class="logo">
            <span class="logo-icon">&#9762;</span>
            <span class="logo-text">NmapAI</span>
          </div>
          <h2>Sign In</h2>
          <p>AI-Assisted Network Scanner</p>
          <div id="login-form">
            <div class="form-group">
              <label class="form-label">Username</label>
              <input type="text" class="form-input" id="loginUsername" placeholder="Enter username" autocomplete="username">
            </div>
            <div class="form-group">
              <label class="form-label">Password</label>
              <input type="password" class="form-input" id="loginPassword" placeholder="Enter password" autocomplete="current-password">
            </div>
            <button class="btn btn-primary" style="width:100%" id="loginSubmitBtn" onclick="app._submitLogin()">Sign In</button>
            <div class="auth-toggle">
              Don't have an account? <a onclick="app.showRegister()">Register</a>
            </div>
          </div>
        </div>
      </div>`);

    document.getElementById('loginUsername').addEventListener('keydown', e => {
      if (e.key === 'Enter') document.getElementById('loginPassword').focus();
    });
    document.getElementById('loginPassword').addEventListener('keydown', e => {
      if (e.key === 'Enter') this._submitLogin();
    });
  }

  async _submitLogin() {
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    if (!username || !password) {
      this.showToast('Please enter username and password', 'warning');
      return;
    }

    const btn = document.getElementById('loginSubmitBtn');
    btn.disabled = true;
    btn.textContent = 'Signing in...';

    try {
      await this.api.login(username, password);
      this.user = await this.api.getMe();
      this._updateUserUI();
      window.location.hash = 'dashboard';
      this.showToast('Login successful', 'success');
    } catch (e) {
      this.showToast(e.message || 'Login failed', 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Sign In';
    }
  }

  showRegister() {
    this._show(`
      <div class="login-container">
        <div class="login-card">
          <div class="logo">
            <span class="logo-icon">&#9762;</span>
            <span class="logo-text">NmapAI</span>
          </div>
          <h2>Create Account</h2>
          <p>Register a new account</p>
          <div id="register-form">
            <div class="form-group">
              <label class="form-label">Username</label>
              <input type="text" class="form-input" id="regUsername" placeholder="Choose a username">
            </div>
            <div class="form-group">
              <label class="form-label">Email</label>
              <input type="email" class="form-input" id="regEmail" placeholder="your@email.com">
            </div>
            <div class="form-group">
              <label class="form-label">Password</label>
              <input type="password" class="form-input" id="regPassword" placeholder="Create a password">
            </div>
            <button class="btn btn-primary" style="width:100%" id="registerSubmitBtn" onclick="app._submitRegister()">Create Account</button>
            <div class="auth-toggle">
              Already have an account? <a onclick="app.showLogin()">Sign In</a>
            </div>
          </div>
        </div>
      </div>`);
  }

  async _submitRegister() {
    const username = document.getElementById('regUsername').value.trim();
    const email = document.getElementById('regEmail').value.trim();
    const password = document.getElementById('regPassword').value;

    if (!username || !email || !password) {
      this.showToast('Please fill in all fields', 'warning');
      return;
    }

    const btn = document.getElementById('registerSubmitBtn');
    btn.disabled = true;
    btn.textContent = 'Creating account...';

    try {
      await this.api.register(username, email, password);
      this.showToast('Account created! Please sign in.', 'success');
      this.showLogin();
    } catch (e) {
      this.showToast(e.message || 'Registration failed', 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Create Account';
    }
  }

  logout() {
    this.api._setToken(null);
    this.user = null;
    this.scans = [];
    this.targets = [];
    this.scanCache = {};
    if (this.ws) { this.ws.close(); this.ws = null; }
    window.location.hash = '';
    this.showLogin();
    this.showToast('Logged out', 'info');
  }

  // --- Dashboard ---
  async showDashboard() {
    let recentScans = [];
    let targetCount = 0;
    let hostCount = 0;
    let openPorts = 0;

    try {
      recentScans = await this.api.getScans() || [];
      this.scans = recentScans;
    } catch (e) { /* ignore */ }

    try {
      const targets = await this.api.getTargets() || [];
      this.targets = targets;
      targetCount = targets.length;
    } catch (e) { /* ignore */ }

    const running = recentScans.filter(s => s.status === 'running' || s.status === 'pending').length;
    const completed = recentScans.filter(s => s.status === 'completed').length;
    const failed = recentScans.filter(s => s.status === 'failed').length;

    this._show(`
      <div class="page-header">
        <div>
          <h1 class="page-title">Dashboard</h1>
          <p class="page-subtitle">Overview of your scanning activity</p>
        </div>
        <div class="btn-group">
          <button class="btn btn-primary" onclick="app._openNewScan()">New Scan</button>
          <button class="btn btn-secondary" onclick="app._openNewTarget()">Add Target</button>
        </div>
      </div>
      <div class="card-grid">
        <div class="stat-card info">
          <span class="stat-label">Total Targets</span>
          <span class="stat-value">${targetCount}</span>
        </div>
        <div class="stat-card accent">
          <span class="stat-label">Total Scans</span>
          <span class="stat-value">${recentScans.length}</span>
        </div>
        <div class="stat-card success">
          <span class="stat-label">Completed</span>
          <span class="stat-value">${completed}</span>
        </div>
        <div class="stat-card warning">
          <span class="stat-label">Running</span>
          <span class="stat-value">${running}</span>
        </div>
        <div class="stat-card danger">
          <span class="stat-label">Failed</span>
          <span class="stat-value">${failed}</span>
        </div>
      </div>
      <div class="card">
        <div class="card-header">
          <span class="card-title">Recent Scans</span>
          <button class="btn btn-sm btn-outline" onclick="window.location.hash='scans'">View All</button>
        </div>
        ${this._renderScansTable(recentScans.slice(0, 10))}
      </div>
      <div class="card" style="margin-top:16px">
        <div class="card-header">
          <span class="card-title">Quick Actions</span>
        </div>
        <div class="btn-group">
          <button class="btn btn-secondary" onclick="app._openNewScan()">Launch Scan</button>
          <button class="btn btn-secondary" onclick="app._openNewTarget()">Add Target</button>
          <button class="btn btn-secondary" onclick="window.location.hash='ai-insights'">AI Analysis</button>
          <button class="btn btn-secondary" onclick="window.location.hash='reports'">Export Reports</button>
        </div>
      </div>`);
  }

  // --- Scans ---
  async showScans() {
    try {
      this.scans = await this.api.getScans() || [];
    } catch (e) {
      this.showToast('Failed to load scans', 'error');
    }

    const statusFilter = this._scanStatusFilter || '';

    this._show(`
      <div class="page-header">
        <div>
          <h1 class="page-title">Scans</h1>
          <p class="page-subtitle">Manage and monitor network scans</p>
        </div>
        <button class="btn btn-primary" onclick="app._openNewScan()">New Scan</button>
      </div>
      <div class="filter-bar">
        <button class="filter-btn ${!statusFilter ? 'active' : ''}" onclick="app._scanStatusFilter=''; app.showScans()">All</button>
        <button class="filter-btn ${statusFilter === 'running' ? 'active' : ''}" onclick="app._scanStatusFilter='running'; app.showScans()">Running</button>
        <button class="filter-btn ${statusFilter === 'completed' ? 'active' : ''}" onclick="app._scanStatusFilter='completed'; app.showScans()">Completed</button>
        <button class="filter-btn ${statusFilter === 'failed' ? 'active' : ''}" onclick="app._scanStatusFilter='failed'; app.showScans()">Failed</button>
        <button class="filter-btn ${statusFilter === 'pending' ? 'active' : ''}" onclick="app._scanStatusFilter='pending'; app.showScans()">Pending</button>
        <button class="filter-btn ${statusFilter === 'paused' ? 'active' : ''}" onclick="app._scanStatusFilter='paused'; app.showScans()">Paused</button>
      </div>
      ${this._renderScansTable(statusFilter ? this.scans.filter(s => s.status === statusFilter) : this.scans)}
    `);
  }

  _renderScansTable(scans) {
    if (!scans || scans.length === 0) {
      return `<div class="empty-state">
        <div class="empty-state-icon">&#9881;</div>
        <div class="empty-state-text">No scans found</div>
        <div class="empty-state-hint">Launch your first scan to get started</div>
      </div>`;
    }

    return `<div class="table-container"><table>
      <thead><tr>
        <th>Name</th>
        <th>Status</th>
        <th>Progress</th>
        <th>Target ID</th>
        <th>Started</th>
        <th>Actions</th>
      </tr></thead>
      <tbody>${scans.map(s => `<tr>
        <td><a style="color:var(--accent);cursor:pointer;text-decoration:none" onclick="app.showScanDetail(${s.id})">${this._escapeHtml(s.name)}</a></td>
        <td>${this._statusBadge(s.status)}</td>
        <td style="min-width:120px">${this._progressBar(s.progress || 0, s.status)}</td>
        <td>${s.target_id || '-'}</td>
        <td>${s.started_at ? this._formatDate(s.started_at) : '-'}</td>
        <td>${this._scanActions(s)}</td>
      </tr>`).join('')}</tbody>
    </table></div>`;
  }

  _scanActions(s) {
    const btns = [];
    btns.push(`<button class="btn btn-xs btn-outline" onclick="app.showScanDetail(${s.id})">View</button>`);
    if (s.status === 'running' || s.status === 'pending') {
      btns.push(`<button class="btn btn-xs btn-danger" onclick="app._cancelScan(${s.id})">Cancel</button>`);
    }
    if (s.status === 'running') {
      btns.push(`<button class="btn btn-xs btn-secondary" onclick="app._pauseScan(${s.id})">Pause</button>`);
    }
    if (s.status === 'paused') {
      btns.push(`<button class="btn btn-xs btn-primary" onclick="app._resumeScan(${s.id})">Resume</button>`);
    }
    return btns.join(' ');
  }

  async _cancelScan(id) {
    if (!confirm('Cancel this scan?')) return;
    try {
      await this.api.cancelScan(id);
      this.showToast('Scan cancelled', 'info');
      this.showScans();
    } catch (e) {
      this.showToast(e.message, 'error');
    }
  }

  async _pauseScan(id) {
    try {
      await this.api.pauseScan(id);
      this.showToast('Scan paused', 'info');
      this.showScans();
    } catch (e) {
      this.showToast(e.message, 'error');
    }
  }

  async _resumeScan(id) {
    try {
      await this.api.resumeScan(id);
      this.showToast('Scan resumed', 'info');
      this.showScans();
    } catch (e) {
      this.showToast(e.message, 'error');
    }
  }

  // --- Scan Detail ---
  async showScanDetail(id) {
    this.selectedScanId = id;
    let scan = this.scans.find(s => s.id === id);
    if (!scan) {
      try {
        scan = await this.api.getScanStatus(id);
      } catch (e) {
        this.showToast('Failed to load scan details', 'error');
        this.showScans();
        return;
      }
    }

    this._show(`
      <div class="page-header">
        <div>
          <h1 class="page-title">${this._escapeHtml(scan.name)}</h1>
          <p class="page-subtitle">Scan #${scan.id} details</p>
        </div>
        <div class="btn-group">
          <button class="btn btn-sm btn-outline" onclick="window.location.hash='scans'">Back to Scans</button>
          ${scan.status === 'completed' ? `<button class="btn btn-sm btn-primary" onclick="app._openAIForScan(${id})">AI Analysis</button>` : ''}
        </div>
      </div>
      <div class="card" style="margin-bottom:20px">
        <div class="detail-grid">
          <div class="detail-item">
            <span class="detail-label">Status</span>
            <span class="detail-value">${this._statusBadge(scan.status)}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Progress</span>
            <span class="detail-value">${scan.progress || 0}%</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Target ID</span>
            <span class="detail-value">${scan.target_id || '-'}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Profile ID</span>
            <span class="detail-value">${scan.profile_id || '-'}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Started</span>
            <span class="detail-value">${scan.started_at ? this._formatDate(scan.started_at) : 'Not started'}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Completed</span>
            <span class="detail-value">${scan.completed_at ? this._formatDate(scan.completed_at) : '-'}</span>
          </div>
        </div>
        ${this._progressBar(scan.progress || 0, scan.status, true)}
      </div>
      <div class="tabs" id="scanTabs">
        <button class="tab active" data-tab="results" onclick="app._switchScanTab('results', ${id})">Results</button>
        <button class="tab" data-tab="hosts" onclick="app._switchScanTab('hosts', ${id})">Hosts</button>
        <button class="tab" data-tab="ai" onclick="app._switchScanTab('ai', ${id})">AI Insights</button>
        <button class="tab" data-tab="raw" onclick="app._switchScanTab('raw', ${id})">Raw Output</button>
      </div>
      <div id="scanTabContent">
        <div class="loading-inline"><div class="spinner spinner-sm"></div> Loading results...</div>
      </div>
    `);

    if (scan.status === 'running' || scan.status === 'pending') {
      this.setupWebSocket(id);
    }

    this._loadScanTab('results', id);
  }

  async _switchScanTab(tab, scanId) {
    document.querySelectorAll('#scanTabs .tab').forEach(t => t.classList.remove('active'));
    document.querySelector(`#scanTabs .tab[data-tab="${tab}"]`).classList.add('active');
    this._loadScanTab(tab, scanId);
  }

  async _loadScanTab(tab, scanId) {
    const container = document.getElementById('scanTabContent');
    container.innerHTML = '<div class="loading-inline"><div class="spinner spinner-sm"></div> Loading...</div>';

    try {
      switch (tab) {
        case 'results': await this._renderResults(scanId, container); break;
        case 'hosts': await this._renderHosts(scanId, container); break;
        case 'ai': await this._renderAITab(scanId, container); break;
        case 'raw': await this._renderRaw(scanId, container); break;
      }
    } catch (e) {
      container.innerHTML = `<div class="empty-state">
        <div class="empty-state-icon">&#9888;</div>
        <div class="empty-state-text">Failed to load ${tab}</div>
        <div class="empty-state-hint">${this._escapeHtml(e.message)}</div>
      </div>`;
    }
  }

  async _renderResults(scanId, container) {
    const results = await this.api.getScanResults(scanId);
    if (!results || !results.hosts || results.hosts.length === 0) {
      container.innerHTML = `<div class="empty-state">
        <div class="empty-state-icon">&#9733;</div>
        <div class="empty-state-text">No results yet</div>
        <div class="empty-state-hint">Scan may still be in progress</div>
      </div>`;
      return;
    }

    container.innerHTML = `
      <div style="margin-bottom:16px;display:flex;gap:12px;flex-wrap:wrap">
        <span class="badge badge-info">${results.host_count || results.hosts.length} Hosts</span>
        <span class="badge badge-neutral">${results.port_count || 0} Ports</span>
      </div>
      ${results.hosts.map(h => this._renderHostCard(h)).join('')}`;
  }

  _renderHostCard(host) {
    const ports = host.ports || [];
    return `<div class="host-card">
      <div class="host-header">
        <div>
          <div class="host-ip">${this._escapeHtml(host.ip)}</div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:4px">
            ${host.hostname ? this._escapeHtml(host.hostname) : ''}
            ${host.os_guess ? `| OS: ${this._escapeHtml(host.os_guess)}` : ''}
            ${host.mac_addr ? `| MAC: ${this._escapeHtml(host.mac_addr)}` : ''}
          </div>
        </div>
        <div>
          ${host.is_alive ? '<span class="badge badge-success">Alive</span>' : '<span class="badge badge-danger">Dead</span>'}
          ${host.latency_ms ? `<span class="badge badge-neutral">${host.latency_ms.toFixed(1)}ms</span>` : ''}
        </div>
      </div>
      ${ports.length > 0 ? `
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px">Open Ports (${ports.length})</div>
        <div class="host-ports">${ports.map(p => this._renderPortBadge(p)).join('')}</div>
      ` : '<div style="color:var(--text-muted);font-size:12px">No open ports found</div>'}
    </div>`;
  }

  _renderPortBadge(port) {
    const cls = port.state === 'open' ? 'open' : port.state === 'filtered' ? 'filtered' : 'closed';
    const label = `${port.port}/${port.protocol || 'tcp'}`;
    const service = port.service_name ? ` ${port.service_name}` : '';
    const version = port.service_version ? ` ${port.service_version}` : '';
    return `<span class="port-badge ${cls}" title="${this._escapeHtml(service + version)}">${label}${service}</span>`;
  }

  async _renderHosts(scanId, container) {
    const hosts = await this.api.getHosts(scanId);
    if (!hosts || hosts.length === 0) {
      container.innerHTML = `<div class="empty-state">
        <div class="empty-state-icon">&#9733;</div>
        <div class="empty-state-text">No hosts discovered</div>
      </div>`;
      return;
    }
    container.innerHTML = hosts.map(h => this._renderHostCard(h)).join('');
  }

  async _renderAITab(scanId, container) {
    container.innerHTML = `
      <div class="btn-group" style="margin-bottom:16px">
        <button class="btn btn-sm btn-primary" onclick="app._summarizeScan(${scanId})">Summarize</button>
        <button class="btn btn-sm btn-secondary" onclick="app._riskScoreScan(${scanId})">Risk Score</button>
        <button class="btn btn-sm btn-secondary" onclick="app._recommendScan(${scanId})">Recommendations</button>
        <button class="btn btn-sm btn-secondary" onclick="app._fetchInsights(${scanId})">Load Insights</button>
      </div>
      <div id="aiOutput" class="empty-state">
        <div class="empty-state-icon">&#9889;</div>
        <div class="empty-state-text">AI Analysis</div>
        <div class="empty-state-hint">Click a button above to analyze this scan</div>
      </div>`;
  }

  async _summarizeScan(scanId) {
    const output = document.getElementById('aiOutput');
    output.innerHTML = '<div class="loading-inline"><div class="spinner spinner-sm"></div> Generating summary...</div>';
    try {
      const result = await this.api.summarize(scanId);
      output.innerHTML = `<div class="insight-card">
        <div class="insight-header"><span class="insight-icon">&#9889;</span><span class="insight-title">AI Summary</span></div>
        <div class="insight-body">${this._escapeHtml(result.summary || JSON.stringify(result))}</div>
      </div>`;
    } catch (e) {
      output.innerHTML = `<div class="empty-state"><div class="empty-state-icon">&#9888;</div><div class="empty-state-text">${this._escapeHtml(e.message)}</div></div>`;
    }
  }

  async _riskScoreScan(scanId) {
    const output = document.getElementById('aiOutput');
    output.innerHTML = '<div class="loading-inline"><div class="spinner spinner-sm"></div> Calculating risk score...</div>';
    try {
      const result = await this.api.riskScore(scanId);
      const score = result.risk_score || result.score || 0;
      const level = score < 30 ? 'low' : score < 60 ? 'medium' : score < 85 ? 'high' : 'critical';
      output.innerHTML = `
        <div class="risk-meter">
          <div class="risk-gauge risk-${level}">
            <div class="risk-score risk-${level}">${score}</div>
          </div>
          <div class="risk-label risk-${level}">${level.toUpperCase()} RISK</div>
          <div style="color:var(--text-secondary);font-size:13px;margin-top:8px">${this._escapeHtml(result.reason || result.detail || '')}</div>
        </div>`;
    } catch (e) {
      output.innerHTML = `<div class="empty-state"><div class="empty-state-icon">&#9888;</div><div class="empty-state-text">${this._escapeHtml(e.message)}</div></div>`;
    }
  }

  async _recommendScan(scanId) {
    const output = document.getElementById('aiOutput');
    output.innerHTML = '<div class="loading-inline"><div class="spinner spinner-sm"></div> Generating recommendations...</div>';
    try {
      const result = await this.api.recommend(scanId);
      output.innerHTML = `<div class="insight-card">
        <div class="insight-header"><span class="insight-icon">&#9889;</span><span class="insight-title">Recommendations</span></div>
        <div class="insight-body">${this._escapeHtml(result.recommendations || result.summary || JSON.stringify(result))}</div>
      </div>`;
    } catch (e) {
      output.innerHTML = `<div class="empty-state"><div class="empty-state-icon">&#9888;</div><div class="empty-state-text">${this._escapeHtml(e.message)}</div></div>`;
    }
  }

  async _fetchInsights(scanId) {
    const output = document.getElementById('aiOutput');
    output.innerHTML = '<div class="loading-inline"><div class="spinner spinner-sm"></div> Loading insights...</div>';
    try {
      const result = await this.api.getAIInsights(scanId);
      output.innerHTML = `<div class="insight-card">
        <div class="insight-header"><span class="insight-icon">&#9889;</span><span class="insight-title">Insights</span></div>
        <div class="insight-body">${this._escapeHtml(JSON.stringify(result, null, 2))}</div>
      </div>`;
    } catch (e) {
      output.innerHTML = `<div class="empty-state"><div class="empty-state-icon">&#9888;</div><div class="empty-state-text">${this._escapeHtml(e.message)}</div></div>`;
    }
  }

  async _renderRaw(scanId, container) {
    try {
      const raw = await this.api.getScanRaw(scanId);
      container.innerHTML = `<div class="code-block">${this._escapeHtml(typeof raw === 'string' ? raw : JSON.stringify(raw, null, 2))}</div>`;
    } catch (e) {
      container.innerHTML = `<div class="code-block" style="color:var(--danger)">Failed to load raw output: ${this._escapeHtml(e.message)}</div>`;
    }
  }

  // --- Targets ---
  async showTargets() {
    try {
      this.targets = await this.api.getTargets() || [];
    } catch (e) {
      this.showToast('Failed to load targets', 'error');
    }

    this._show(`
      <div class="page-header">
        <div>
          <h1 class="page-title">Targets</h1>
          <p class="page-subtitle">Manage scan targets</p>
        </div>
        <button class="btn btn-primary" onclick="app._openNewTarget()">Add Target</button>
      </div>
      ${this._renderTargetsTable()}
    `);
  }

  _renderTargetsTable() {
    if (!this.targets || this.targets.length === 0) {
      return `<div class="empty-state">
        <div class="empty-state-icon">&#9733;</div>
        <div class="empty-state-text">No targets defined</div>
        <div class="empty-state-hint">Add a target to start scanning</div>
      </div>`;
    }

    return `<div class="table-container"><table>
      <thead><tr>
        <th>Name</th>
        <th>Target</th>
        <th>Type</th>
        <th>Project</th>
        <th>Tags</th>
        <th>Created</th>
        <th>Actions</th>
      </tr></thead>
      <tbody>${this.targets.map(t => `<tr>
        <td><strong>${this._escapeHtml(t.name)}</strong></td>
        <td style="color:var(--accent);font-weight:600">${this._escapeHtml(t.target_value)}</td>
        <td><span class="badge badge-neutral">${this._escapeHtml(t.target_type)}</span></td>
        <td>${t.project ? this._escapeHtml(t.project) : '-'}</td>
        <td>${t.tags && t.tags.length > 0 ? t.tags.map(tag => `<span class="tag">${this._escapeHtml(tag)}</span>`).join(' ') : '-'}</td>
        <td>${this._formatDate(t.created_at)}</td>
        <td>
          <button class="btn btn-xs btn-outline" onclick="app._openScanForTarget(${t.id}, '${this._escapeHtml(t.name)}')">Scan</button>
          <button class="btn btn-xs btn-danger" onclick="app._deleteTarget(${t.id})">Delete</button>
        </td>
      </tr>`).join('')}</tbody>
    </table></div>`;
  }

  async _deleteTarget(id) {
    if (!confirm('Delete this target?')) return;
    try {
      await this.api.deleteTarget(id);
      this.showToast('Target deleted', 'success');
      this.showTargets();
    } catch (e) {
      this.showToast(e.message, 'error');
    }
  }

  _openNewTarget() {
    this._showModal('Add Target', `
      <form id="targetForm" onsubmit="event.preventDefault(); app._submitTarget()">
        <div class="form-group">
          <label class="form-label">Name</label>
          <input type="text" class="form-input" id="targetName" placeholder="My Target" required>
        </div>
        <div class="form-group">
          <label class="form-label">Target Value</label>
          <input type="text" class="form-input" id="targetValue" placeholder="e.g. 192.168.1.0/24, example.com" required>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Type</label>
            <select class="form-select" id="targetType">
              <option value="ip">IP Address</option>
              <option value="cidr">CIDR Range</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Project</label>
            <input type="text" class="form-input" id="targetProject" placeholder="Project name">
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Tags</label>
          <div class="tag-input-container" id="tagInputContainer" onclick="document.getElementById('tagInput').focus()">
            <div id="tagList" style="display:flex;flex-wrap:wrap;gap:6px"></div>
            <input type="text" id="tagInput" placeholder="Add tag..." onkeydown="app._handleTagKey(event)">
          </div>
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%" id="targetSubmitBtn">Add Target</button>
      </form>
    `);

    window._targetTags = [];
  }

  _handleTagKey(e) {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      const input = document.getElementById('tagInput');
      const tag = input.value.trim();
      if (tag && !window._targetTags.includes(tag)) {
        window._targetTags.push(tag);
        this._renderTags();
      }
      input.value = '';
    } else if (e.key === 'Backspace' && !e.target.value) {
      window._targetTags.pop();
      this._renderTags();
    }
  }

  _renderTags() {
    const container = document.getElementById('tagList');
    if (container) {
      container.innerHTML = (window._targetTags || []).map((tag, i) =>
        `<span class="tag">${this._escapeHtml(tag)} <span class="tag-remove" onclick="app._removeTag(${i})">&times;</span></span>`
      ).join('');
    }
  }

  _removeTag(i) {
    window._targetTags.splice(i, 1);
    this._renderTags();
  }

  async _submitTarget() {
    const name = document.getElementById('targetName').value.trim();
    const value = document.getElementById('targetValue').value.trim();
    const type = document.getElementById('targetType').value;
    const project = document.getElementById('targetProject').value.trim();
    const tags = window._targetTags || [];

    if (!name || !value) {
      this.showToast('Name and target value are required', 'warning');
      return;
    }

    const btn = document.getElementById('targetSubmitBtn');
    btn.disabled = true;
    btn.textContent = 'Adding...';

    try {
      await this.api.createTarget(name, value, type, project, tags);
      this.closeModal();
      this.showToast('Target added successfully', 'success');
      this.showTargets();
    } catch (e) {
      this.showToast(e.message, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Add Target';
    }
  }

  _openScanForTarget(targetId, targetName) {
    this._openNewScan(targetId, targetName);
  }

  // --- Scan Profiles ---
  async showProfiles() {
    try {
      this.profiles = await this.api.getScanProfiles() || [];
    } catch (e) {
      this.showToast('Failed to load profiles', 'error');
    }

    this._show(`
      <div class="page-header">
        <div>
          <h1 class="page-title">Scan Profiles</h1>
          <p class="page-subtitle">Predefined and custom scan configurations</p>
        </div>
        <button class="btn btn-primary" onclick="app._openNewProfile()">Create Profile</button>
      </div>
      ${this._renderProfilesGrid()}
    `);
  }

  _renderProfilesGrid() {
    if (!this.profiles || this.profiles.length === 0) {
      return `<div class="empty-state">
        <div class="empty-state-icon">&#9881;</div>
        <div class="empty-state-text">No profiles available</div>
      </div>`;
    }

    return `<div class="card-grid">${this.profiles.map(p => `
      <div class="card" style="display:flex;flex-direction:column">
        <div class="card-header">
          <span class="card-title">${this._escapeHtml(p.name)}</span>
          ${p.is_builtin ? '<span class="badge badge-neutral">Built-in</span>' : '<span class="badge badge-info">Custom</span>'}
        </div>
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:12px;flex:1">
          <div>${this._escapeHtml(p.description || 'No description')}</div>
          <div style="margin-top:8px">
            <span class="badge badge-neutral">${this._escapeHtml(p.scan_type)}</span>
            <span class="badge badge-neutral">${this._escapeHtml(p.timing)}</span>
            <span class="badge badge-neutral">${this._escapeHtml(p.ports)}</span>
          </div>
        </div>
        <button class="btn btn-sm btn-outline" onclick="app._openNewScan(null, '${this._escapeHtml(p.name)}', ${p.id})">Use Profile</button>
      </div>
    `).join('')}</div>`;
  }

  _openNewProfile() {
    this._showModal('Create Scan Profile', `
      <form id="profileForm" onsubmit="event.preventDefault(); app._submitProfile()">
        <div class="form-group">
          <label class="form-label">Profile Name</label>
          <input type="text" class="form-input" id="profileName" placeholder="My Profile" required>
        </div>
        <div class="form-group">
          <label class="form-label">Description</label>
          <textarea class="form-textarea" id="profileDesc" placeholder="Optional description"></textarea>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Scan Type</label>
            <select class="form-select" id="profileScanType">
              <option value="tcp_connect">TCP Connect</option>
              <option value="syn">SYN Stealth</option>
              <option value="udp">UDP</option>
              <option value="fin">FIN</option>
              <option value="xmas">XMAS</option>
              <option value="null">Null</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Timing</label>
            <select class="form-select" id="profileTiming">
              <option value="T0">T0 - Paranoid</option>
              <option value="T1">T1 - Sneaky</option>
              <option value="T2">T2 - Polite</option>
              <option value="T3" selected>T3 - Normal</option>
              <option value="T4">T4 - Aggressive</option>
              <option value="T5">T5 - Insane</option>
            </select>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Ports</label>
          <input type="text" class="form-input" id="profilePorts" placeholder="e.g. 22,80,443 or 1-1000" value="22,80,443,8080,8443">
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">UDP Ports</label>
            <input type="text" class="form-input" id="profileUDP" placeholder="e.g. 53,67,68">
          </div>
          <div class="form-group" style="display:flex;gap:16px;padding-top:24px">
            <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px">
              <input type="checkbox" id="profileServiceDetect" checked> Service Detect
            </label>
            <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px">
              <input type="checkbox" id="profileOSDetect"> OS Detect
            </label>
            <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px">
              <input type="checkbox" id="profileDiscovery" checked> Discovery
            </label>
          </div>
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%" id="profileSubmitBtn">Create Profile</button>
      </form>
    `);
  }

  async _submitProfile() {
    const data = {
      name: document.getElementById('profileName').value.trim(),
      description: document.getElementById('profileDesc').value.trim(),
      scan_type: document.getElementById('profileScanType').value,
      timing: document.getElementById('profileTiming').value,
      ports: document.getElementById('profilePorts').value.trim(),
      udp_ports: document.getElementById('profileUDP').value.trim() || null,
      service_detect: document.getElementById('profileServiceDetect').checked,
      os_detect: document.getElementById('profileOSDetect').checked,
      discovery: document.getElementById('profileDiscovery').checked,
    };

    if (!data.name || !data.ports) {
      this.showToast('Name and ports are required', 'warning');
      return;
    }

    const btn = document.getElementById('profileSubmitBtn');
    btn.disabled = true;
    btn.textContent = 'Creating...';

    try {
      await this.api.createScanProfile(data);
      this.closeModal();
      this.showToast('Profile created', 'success');
      this.showProfiles();
    } catch (e) {
      this.showToast(e.message, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Create Profile';
    }
  }

  // --- New Scan Modal ---
  async _openNewScan(targetId, targetName, profileId) {
    let targets = this.targets;
    let profiles = this.profiles;
    try {
      if (!targets.length) targets = await this.api.getTargets() || [];
      if (!profiles.length) profiles = await this.api.getScanProfiles() || [];
    } catch (e) { /* ignore */ }

    this._showModal('Launch Scan', `
      <form id="scanForm" onsubmit="event.preventDefault(); app._submitScan()">
        <div class="form-group">
          <label class="form-label">Scan Name</label>
          <input type="text" class="form-input" id="scanName" placeholder="My Scan" value="${targetName ? 'Scan - ' + this._escapeHtml(targetName) : ''}" required>
        </div>
        <div class="form-group">
          <label class="form-label">Target</label>
          <select class="form-select" id="scanTarget" required>
            <option value="">Select a target...</option>
            ${targets.map(t => `<option value="${t.id}" ${targetId == t.id ? 'selected' : ''}>${this._escapeHtml(t.name)} (${this._escapeHtml(t.target_value)})</option>`).join('')}
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">Scan Profile</label>
          <select class="form-select" id="scanProfile" required>
            <option value="">Select a profile...</option>
            ${profiles.map(p => `<option value="${p.id}" ${profileId == p.id ? 'selected' : ''}>${this._escapeHtml(p.name)}${p.is_builtin ? ' [Built-in]' : ''}</option>`).join('')}
          </select>
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%" id="scanSubmitBtn">Launch Scan</button>
      </form>
    `);
  }

  async _submitScan() {
    const name = document.getElementById('scanName').value.trim();
    const targetId = parseInt(document.getElementById('scanTarget').value);
    const profileId = document.getElementById('scanProfile').value;

    if (!name || !targetId || !profileId) {
      this.showToast('All fields are required', 'warning');
      return;
    }

    const btn = document.getElementById('scanSubmitBtn');
    btn.disabled = true;
    btn.textContent = 'Launching...';

    try {
      const scan = await this.api.launchScan(name, targetId, profileId);
      this.closeModal();
      this.showToast('Scan launched successfully', 'success');
      window.location.hash = 'scans';
      if (scan && scan.id) {
        this.setupWebSocket(scan.id);
      }
    } catch (e) {
      this.showToast(e.message, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Launch Scan';
    }
  }

  // --- AI Insights ---
  async showAIInsights() {
    let scans = [];
    try {
      scans = await this.api.getScans() || [];
    } catch (e) { /* ignore */ }

    const completedScans = scans.filter(s => s.status === 'completed');

    this._show(`
      <div class="page-header">
        <div>
          <h1 class="page-title">AI Insights</h1>
          <p class="page-subtitle">AI-powered analysis of scan results</p>
        </div>
      </div>
      <div class="card" style="margin-bottom:16px">
        <div class="card-header"><span class="card-title">Select Scan for Analysis</span></div>
        <div class="form-row" style="padding:8px 0">
          <div class="form-group">
            <label class="form-label">Scan</label>
            <select class="form-select" id="aiScanSelect" onchange="app._insightScanId=parseInt(this.value); app._loadAIInsights()">
              <option value="">Select a completed scan...</option>
              ${completedScans.map(s => `<option value="${s.id}">${this._escapeHtml(s.name)} (#${s.id})</option>`).join('')}
              ${scans.filter(s => s.status !== 'completed').map(s => `<option value="${s.id}" disabled>${this._escapeHtml(s.name)} (${s.status})</option>`).join('')}
            </select>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Analysis</span></div>
        <div class="btn-group" style="margin-bottom:16px">
          <button class="btn btn-sm btn-primary" onclick="app._analyzeScan('summarize')">Summarize</button>
          <button class="btn btn-sm btn-secondary" onclick="app._analyzeScan('risk')">Risk Score</button>
          <button class="btn btn-sm btn-secondary" onclick="app._analyzeScan('recommend')">Recommend</button>
          <button class="btn btn-sm btn-secondary" onclick="app._analyzeScan('insights')">Insights</button>
        </div>
        <div class="form-group">
          <label class="form-label">Ask a Question</label>
          <div style="display:flex;gap:8px">
            <input type="text" class="form-input" id="aiQueryInput" placeholder="e.g. Which ports are vulnerable?" onkeydown="if(event.key==='Enter')app._askQuestion()">
            <button class="btn btn-primary" onclick="app._askQuestion()">Ask</button>
            <button class="btn btn-secondary" onclick="app._openChat()">&#128172; Chat</button>
          </div>
        </div>
        <div id="aiInsightsOutput" class="empty-state" style="padding:20px">
          <div class="empty-state-icon">&#9889;</div>
          <div class="empty-state-text">Select a scan and run analysis</div>
        </div>
      </div>
      <div class="card" style="margin-top:16px">
        <div class="card-header"><span class="card-title">Compare Scans</span></div>
        <div class="compare-container">
          <div class="form-group">
            <label class="form-label">Scan A</label>
            <select class="form-select" id="compareScan1">
              <option value="">Select...</option>
              ${completedScans.map(s => `<option value="${s.id}">${this._escapeHtml(s.name)} (#${s.id})</option>`).join('')}
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Scan B</label>
            <select class="form-select" id="compareScan2">
              <option value="">Select...</option>
              ${completedScans.map(s => `<option value="${s.id}">${this._escapeHtml(s.name)} (#${s.id})</option>`).join('')}
            </select>
          </div>
        </div>
        <button class="btn btn-secondary" onclick="app._compareScans()">Compare</button>
        <div id="compareOutput" style="margin-top:12px"></div>
      </div>
    `);
  }

  async _analyzeScan(action) {
    const scanId = this._insightScanId;
    if (!scanId) {
      this.showToast('Please select a scan first', 'warning');
      return;
    }
    const output = document.getElementById('aiInsightsOutput');
    output.innerHTML = '<div class="loading-inline"><div class="spinner spinner-sm"></div> Processing...</div>';

    try {
      let result;
      switch (action) {
        case 'summarize':
          result = await this.api.summarize(scanId);
          const riskBadge = result.risk_level ? `<span class="risk-badge risk-${result.risk_level}">${result.risk_level.toUpperCase()}</span>` : '';
          const findings = (result.key_findings || []).length
            ? `<ul class="findings-list">${result.key_findings.map(f => `<li>${this._escapeHtml(f)}</li>`).join('')}</ul>`
            : '';
          const meta = (result.host_summary || result.port_summary)
            ? `<div class="summary-meta">${this._escapeHtml(result.host_summary || '')} ${this._escapeHtml(result.port_summary || '')}</div>`
            : '';
          output.innerHTML = `<div class="insight-card">
            <div class="insight-header"><span class="insight-icon">&#9889;</span><span class="insight-title">Summary ${riskBadge}</span></div>
            <div class="insight-body"><p style="margin:0 0 12px 0">${this._escapeHtml(result.summary || '')}</p>${meta}${findings}</div>
          </div>`;
          break;
        case 'risk':
          result = await this.api.riskScore(scanId);
          const score = result.risk_score || result.score || 0;
          const level = score < 30 ? 'low' : score < 60 ? 'medium' : score < 85 ? 'high' : 'critical';
          const factors = (result.factors || []).length
            ? `<div style="margin-top:12px"><strong>Factors:</strong><ul style="margin:4px 0 0 16px;padding:0">${result.factors.map(f => `<li style="font-size:13px;color:var(--text-secondary)">${this._escapeHtml(f)}</li>`).join('')}</ul></div>`
            : '';
          output.innerHTML = `<div class="risk-meter"><div class="risk-gauge risk-${level}"><div class="risk-score risk-${level}">${score}</div></div><div class="risk-label risk-${level}">${level.toUpperCase()} RISK</div><div style="color:var(--text-secondary);font-size:13px;margin-top:8px">${this._escapeHtml(result.reason || '')}</div>${factors}</div>`;
          break;
        case 'recommend':
          result = await this.api.recommend(scanId);
          if (Array.isArray(result.recommendations) && result.recommendations.length) {
            const cards = result.recommendations.map(r => {
              const p = r.priority || 0;
              const prioClass = p >= 5 ? 'critical' : p >= 4 ? 'high' : p >= 3 ? 'medium' : 'low';
              const cat = r.category || '';
              const title = r.title || r;
              const desc = r.description || '';
              return `<div class="rec-card rec-${prioClass}">
                <div class="rec-priority rec-${prioClass}">${p}</div>
                <div class="rec-content"><strong>${this._escapeHtml(title)}</strong>${desc ? `<div style="font-size:13px;color:var(--text-secondary);margin-top:4px">${this._escapeHtml(desc)}</div>` : ''}${cat ? `<div style="font-size:11px;color:var(--text-tertiary);margin-top:4px">${this._escapeHtml(cat)}</div>` : ''}</div>
              </div>`;
            }).join('');
            output.innerHTML = `<div class="insight-card"><div class="insight-header"><span class="insight-icon">&#9889;</span><span class="insight-title">Recommendations (${result.recommendations.length})</span></div><div class="insight-body" style="padding:8px 16px">${cards}</div></div>`;
          } else {
            output.innerHTML = `<div class="insight-card"><div class="insight-header"><span class="insight-icon">&#9889;</span><span class="insight-title">Recommendations</span></div><div class="insight-body">${this._escapeHtml(result.summary || result.recommendations || JSON.stringify(result))}</div></div>`;
          }
          break;
        case 'insights':
          result = await this.api.getAIInsights(scanId);
          output.innerHTML = `<div class="insight-card"><div class="insight-header"><span class="insight-icon">&#9889;</span><span class="insight-title">Insights</span></div><div class="insight-body"><pre style="white-space:pre-wrap;font-family:inherit;font-size:13px">${this._escapeHtml(JSON.stringify(result, null, 2))}</pre></div></div>`;
          break;
      }
    } catch (e) {
      output.innerHTML = `<div class="empty-state"><div class="empty-state-icon">&#9888;</div><div class="empty-state-text">${this._escapeHtml(e.message)}</div></div>`;
    }
  }

  async _askQuestion() {
    const scanId = this._insightScanId;
    const query = document.getElementById('aiQueryInput').value.trim();
    if (!scanId) { this.showToast('Select a scan first', 'warning'); return; }
    if (!query) { this.showToast('Enter a question', 'warning'); return; }

    const output = document.getElementById('aiInsightsOutput');
    output.innerHTML = '<div class="loading-inline"><div class="spinner spinner-sm"></div> Asking AI...</div>';

    try {
      const result = await this.api.query(query, scanId);
      const conf = result.confidence || 0;
      const confPct = Math.round(conf * 100);
      const confColor = conf >= 0.8 ? 'var(--success)' : conf >= 0.5 ? 'var(--warning)' : 'var(--danger)';
      const confBar = `<div style="margin-top:12px;font-size:12px;color:var(--text-secondary)">Confidence: ${confPct}% <div style="background:var(--bg-tertiary);border-radius:4px;height:6px;margin-top:2px;width:200px;max-width:100%"><div style="background:${confColor};border-radius:4px;height:6px;width:${confPct}%;transition:width 0.3s"></div></div></div>`;
      const evidence = (result.evidence_refs || []).length
        ? `<div style="margin-top:8px;font-size:11px;color:var(--text-tertiary)">Evidence: ${result.evidence_refs.map(r => `<code style="background:var(--bg-tertiary);padding:1px 4px;border-radius:3px">${this._escapeHtml(r)}</code>`).join(' ')}</div>`
        : '';
      output.innerHTML = `<div class="insight-card">
        <div class="insight-header"><span class="insight-icon">&#9889;</span><span class="insight-title">Q: ${this._escapeHtml(query)}</span></div>
        <div class="insight-body">${this._escapeHtml(result.answer || result.response || JSON.stringify(result))}${confBar}${evidence}</div>
      </div>`;
    } catch (e) {
      output.innerHTML = `<div class="empty-state"><div class="empty-state-icon">&#9888;</div><div class="empty-state-text">${this._escapeHtml(e.message)}</div></div>`;
    }
  }

  async _compareScans() {
    const id1 = parseInt(document.getElementById('compareScan1').value);
    const id2 = parseInt(document.getElementById('compareScan2').value);
    if (!id1 || !id2) { this.showToast('Select two scans to compare', 'warning'); return; }
    if (id1 === id2) { this.showToast('Select two different scans', 'warning'); return; }

    const output = document.getElementById('compareOutput');
    output.innerHTML = '<div class="loading-inline"><div class="spinner spinner-sm"></div> Comparing...</div>';

    try {
      const result = await this.api.compare(id1, id2);
      const newHosts = result.new_hosts || [];
      const removedHosts = result.removed_hosts || [];
      const newPorts = result.new_ports || [];
      const removedPorts = result.removed_ports || [];
      const newConcerns = result.new_concerns || [];
      const resolvedConcerns = result.resolved_concerns || [];

      let diffs = '';
      if (newHosts.length || removedHosts.length || newPorts.length || removedPorts.length) {
        const items = [];
        if (newHosts.length) items.push(`<span class="diff-badge diff-added">+${newHosts.length} hosts</span>`);
        if (removedHosts.length) items.push(`<span class="diff-badge diff-removed">-${removedHosts.length} hosts</span>`);
        if (newPorts.length) items.push(`<span class="diff-badge diff-added">+${newPorts.length} ports</span>`);
        if (removedPorts.length) items.push(`<span class="diff-badge diff-removed">-${removedPorts.length} ports</span>`);
        diffs = `<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">${items.join('')}</div>`;
      }
      let concerns = '';
      if (newConcerns.length) concerns += `<div style="margin-top:8px"><strong style="color:var(--danger);font-size:13px">New Concerns:</strong><ul style="margin:4px 0 0 16px">${newConcerns.map(c => `<li style="font-size:13px;color:var(--text-secondary)">${this._escapeHtml(c)}</li>`).join('')}</ul></div>`;
      if (resolvedConcerns.length) concerns += `<div style="margin-top:8px"><strong style="color:var(--success);font-size:13px">Resolved Concerns:</strong><ul style="margin:4px 0 0 16px">${resolvedConcerns.map(c => `<li style="font-size:13px;color:var(--text-secondary)">${this._escapeHtml(c)}</li>`).join('')}</ul></div>`;

      const narrative = result.comparison || result.detail || result.summary || '';
      output.innerHTML = `<div class="insight-card">
        <div class="insight-header"><span class="insight-icon">&#9889;</span><span class="insight-title">Comparison: Scan #${id1} vs #${id2}</span></div>
        <div class="insight-body">${diffs}<p style="margin:0;line-height:1.5">${this._escapeHtml(narrative)}</p>${concerns}</div>
      </div>`;
    } catch (e) {
      output.innerHTML = `<div class="empty-state"><div class="empty-state-icon">&#9888;</div><div class="empty-state-text">${this._escapeHtml(e.message)}</div></div>`;
    }
  }

  _openChat() {
    const scanId = this._insightScanId;
    if (!scanId) { this.showToast('Select a scan first', 'warning'); return; }
    if (document.getElementById('chatModal')) return;

    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.id = 'chatModal';
    modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
    modal.innerHTML = `
      <div class="modal" style="min-width:600px;max-width:700px;height:70vh;display:flex;flex-direction:column">
        <div class="modal-header">
          <h3>&#128172; Chat with AI — Scan #${scanId}</h3>
          <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">&times;</button>
        </div>
        <div class="modal-body" style="flex:1;overflow-y:auto;padding:16px;display:flex;flex-direction:column" id="chatMessages">
          <div style="text-align:center;color:var(--text-muted);font-size:13px;padding:20px">Ask anything about this scan</div>
        </div>
        <div style="padding:12px 16px;border-top:1px solid var(--border);display:flex;gap:8px">
          <input type="text" id="chatInput" class="form-input" placeholder="Ask a question..." style="flex:1"
            onkeydown="if(event.key==='Enter')app._sendChatMessage()">
          <button class="btn btn-primary" onclick="app._sendChatMessage()">Send</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
    setTimeout(() => document.getElementById('chatInput')?.focus(), 100);
  }

  async _sendChatMessage() {
    const input = document.getElementById('chatInput');
    const msgContainer = document.getElementById('chatMessages');
    const scanId = this._insightScanId;
    const text = input.value.trim();
    if (!text || !scanId) return;
    input.value = '';
    input.disabled = true;

    const userMsg = document.createElement('div');
    userMsg.style = 'align-self:flex-end;background:var(--accent-dim);color:var(--accent);padding:8px 14px;border-radius:12px 12px 4px 12px;margin-bottom:12px;max-width:80%;font-size:13px';
    userMsg.textContent = text;
    msgContainer.appendChild(userMsg);

    const botMsg = document.createElement('div');
    botMsg.style = 'align-self:flex-start;background:var(--bg-secondary);padding:8px 14px;border-radius:12px 12px 12px 4px;margin-bottom:12px;max-width:80%;font-size:13px;color:var(--text-secondary);white-space:pre-wrap';
    botMsg.textContent = '...';
    msgContainer.appendChild(botMsg);
    msgContainer.scrollTop = msgContainer.scrollHeight;

    try {
      const resp = await fetch(`/api/v1/ai/query/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${localStorage.getItem('nmapai_token') || ''}` },
        body: JSON.stringify({ query: text, scan_id: scanId }),
      });
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      botMsg.textContent = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.slice(6));
              if (data.done) break;
              if (data.token) botMsg.textContent += data.token;
            } catch (e) { /* skip parse errors */ }
          }
        }
        msgContainer.scrollTop = msgContainer.scrollHeight;
      }
    } catch (e) {
      botMsg.textContent = `Error: ${e.message}`;
    }
    input.disabled = false;
    input.focus();
  }

  async _loadAIInsights() {
    const scanId = this._insightScanId;
    const output = document.getElementById('aiInsightsOutput');
    if (!scanId) {
      output.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#9889;</div><div class="empty-state-text">Select a scan</div></div>';
      return;
    }
    output.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#9889;</div><div class="empty-state-text">Ready</div><div class="empty-state-hint">Click an analysis button above</div></div>';
  }

  // --- Reports ---
  showReports() {
    const completedScans = (this.scans || []).filter(s => s.status === 'completed');

    this._show(`
      <div class="page-header">
        <div>
          <h1 class="page-title">Reports</h1>
          <p class="page-subtitle">Export scan results in various formats</p>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Export Scan Results</span></div>
        <div class="form-group">
          <label class="form-label">Select Scan</label>
          <select class="form-select" id="exportScanSelect">
            <option value="">Select a completed scan...</option>
            ${completedScans.map(s => `<option value="${s.id}">${this._escapeHtml(s.name)} (#${s.id})</option>`).join('')}
          </select>
        </div>
        <div style="display:flex;gap:12px;flex-wrap:wrap">
          <button class="btn btn-secondary" onclick="app._exportScan('json')">Export JSON</button>
          <button class="btn btn-secondary" onclick="app._exportScan('csv')">Export CSV</button>
          <button class="btn btn-secondary" onclick="app._exportScan('pdf')">Export PDF</button>
        </div>
        <div id="exportStatus" style="margin-top:12px"></div>
      </div>
      <div class="card" style="margin-top:16px">
        <div class="card-header"><span class="card-title">AI Reports</span></div>
        <p style="color:var(--text-muted);font-size:13px;margin-bottom:12px">Generate AI-powered analysis reports for completed scans.</p>
        <div class="btn-group">
          <button class="btn btn-secondary" onclick="window.location.hash='ai-insights'">Go to AI Insights</button>
        </div>
      </div>
    `);
  }

  async _exportScan(format) {
    const scanId = parseInt(document.getElementById('exportScanSelect').value);
    if (!scanId) {
      this.showToast('Select a scan to export', 'warning');
      return;
    }

    const status = document.getElementById('exportStatus');
    status.innerHTML = '<div class="loading-inline"><div class="spinner spinner-sm"></div> Exporting...</div>';

    try {
      await this.api.exportScan(scanId, format);
      status.innerHTML = `<span style="color:var(--success)">Export completed successfully</span>`;
      this.showToast(`Exported as ${format.toUpperCase()}`, 'success');
    } catch (e) {
      status.innerHTML = `<span style="color:var(--danger)">${this._escapeHtml(e.message)}</span>`;
      this.showToast(e.message, 'error');
    }
  }

  // --- Admin ---
  async showAdmin() {
    if (!this.user || this.user.role !== 'admin') {
      this._show(`
        <div class="page-header"><div><h1 class="page-title">Admin</h1></div></div>
        <div class="empty-state">
          <div class="empty-state-icon">&#9888;</div>
          <div class="empty-state-text">Access Denied</div>
          <div class="empty-state-hint">Administrator privileges required</div>
        </div>`);
      return;
    }

    try {
      this.users = await this.api.getUsers() || [];
    } catch (e) {
      this.showToast('Failed to load users', 'error');
    }

    this._show(`
      <div class="page-header">
        <div>
          <h1 class="page-title">Admin</h1>
          <p class="page-subtitle">User management</p>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Users</span></div>
        ${this._renderUsersTable()}
      </div>
    `);
  }

  _renderUsersTable() {
    if (!this.users || this.users.length === 0) {
      return '<div class="empty-state"><div class="empty-state-icon">&#9733;</div><div class="empty-state-text">No users found</div></div>';
    }

    return `<div class="table-container"><table>
      <thead><tr>
        <th>ID</th>
        <th>Username</th>
        <th>Email</th>
        <th>Role</th>
        <th>Active</th>
        <th>Actions</th>
      </tr></thead>
      <tbody>${this.users.map(u => `<tr>
        <td>${u.id}</td>
        <td>${this._escapeHtml(u.username)}</td>
        <td>${this._escapeHtml(u.email)}</td>
        <td><span class="badge ${u.role === 'admin' ? 'badge-danger' : u.role === 'operator' ? 'badge-warning' : 'badge-info'}">${this._escapeHtml(u.role)}</span></td>
        <td>${u.is_active ? '<span style="color:var(--success)">Active</span>' : '<span style="color:var(--danger)">Inactive</span>'}</td>
        <td>
          ${u.role !== 'admin' ? `
            <select class="form-select" style="width:auto;display:inline-block;padding:4px 24px 4px 8px;font-size:11px" onchange="app._updateUserRole(${u.id}, this.value)">
              <option value="viewer" ${u.role === 'viewer' ? 'selected' : ''}>Viewer</option>
              <option value="operator" ${u.role === 'operator' ? 'selected' : ''}>Operator</option>
              <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>Admin</option>
            </select>
          ` : '-'}
        </td>
      </tr>`).join('')}</tbody>
    </table></div>`;
  }

  async _updateUserRole(userId, role) {
    try {
      await this.api.updateUserRole(userId, role);
      this.showToast('User role updated', 'success');
    } catch (e) {
      this.showToast(e.message, 'error');
    }
  }

  // --- WebSocket ---
  setupWebSocket(scanId) {
    if (this.ws) {
      this.ws.close();
    }

    this.ws = this.api.connectWebSocket(scanId, (data) => {
      this.updateProgress(data);
    });
  }

  updateProgress(data) {
    if (data.progress !== undefined) {
      const bars = document.querySelectorAll('.progress-fill');
      const texts = document.querySelectorAll('.progress-text');
      bars.forEach(bar => {
        bar.style.width = `${data.progress}%`;
      });
      texts.forEach(t => {
        if (t.querySelector('.progress-label')) {
          t.querySelector('.progress-label').textContent = `Progress: ${data.progress}%`;
        }
      });
    }

    if (data.status) {
      const badges = document.querySelectorAll('.status-indicator');
      badges.forEach(b => {
        const dot = b.querySelector('.status-dot');
        if (dot) {
          dot.className = `status-dot ${data.status}`;
        }
        const label = b.querySelector('.status-label');
        if (label) label.textContent = data.status.toUpperCase();
      });
    }

    if (data.message) {
      this.showToast(data.message, 'info');
    }
  }

  // --- Modal ---
  _showModal(title, bodyHtml) {
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalBody').innerHTML = bodyHtml;
    document.getElementById('modal-overlay').style.display = 'flex';
  }

  closeModal() {
    document.getElementById('modal-overlay').style.display = 'none';
  }

  // --- Toast ---
  showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<span>${this._escapeHtml(message)}</span><button class="toast-close" onclick="this.parentElement.remove()">&times;</button>`;

    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(40px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  // --- Helpers ---
  _statusBadge(status) {
    const map = {
      running: 'success',
      completed: 'info',
      failed: 'danger',
      pending: 'warning',
      paused: 'warning',
      cancelled: 'neutral',
    };
    const cls = map[status] || 'neutral';
    return `<span class="status-indicator"><span class="status-dot ${status}"></span><span class="status-label badge badge-${cls}">${status.toUpperCase()}</span></span>`;
  }

  _progressBar(value, status, showLabel = false) {
    const cls = status === 'running' || status === 'pending' ? 'running' : status === 'failed' ? 'failed' : '';
    return `<div>
      ${showLabel ? `<div class="progress-text"><span class="progress-label">Progress: ${value}%</span></div>` : ''}
      <div class="progress-bar"><div class="progress-fill ${cls}" style="width:${value}%"></div></div>
    </div>`;
  }

  _formatDate(dateStr) {
    if (!dateStr) return '-';
    try {
      const d = new Date(dateStr);
      return d.toLocaleString('en-US', {
        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
      });
    } catch {
      return dateStr;
    }
  }
}

// Initialize
const app = new App();
window.app = app;
document.addEventListener('DOMContentLoaded', () => app.init());
