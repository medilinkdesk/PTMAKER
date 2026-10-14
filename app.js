/**
 * Garment Inventory Verification App Engine - Encrypted & Multi-Role System
 * Features 256-Bit Hardware AES-GCM Encryption, Role Access Control (Admin, Manager, User),
 * WebRTC Multi-Device Sync (PeerJS), Permanent Login Persistence, and Admin Session Management.
 */

// Global State
const state = {
  currentUser: null, // { role: 'ADMIN'|'MANAGER'|'USER', name: 'Ramesh', passcode: '...' }
  currentSession: null,
  excelRawData: null,
  excelHeaders: [],
  excelRows: [],
  zxingReader: null,
  isScanningCamera: false,
  isScanLocked: false, // Locks scanning until user verifies & confirms single item
  activeScanItem: null,
  activeScanRowIndex: null,
  audioCtx: null,
  videoDevices: [],
  currentCameraIndex: 0,
  activeStream: null,
  isTorchOn: false,
  peer: null,
  peerConnections: [],
  isPeerHost: false
};

// Default Credentials Configuration
const ROLE_CREDENTIALS = {
  ADMIN: { pass: 'admin123', label: 'Admin (Full Access)', priv: 'Full Control • Excel Upload • Delete Session & Raw File • Export Reports' },
  MANAGER: { pass: 'mgr123', label: 'Manager (Upload & Export)', priv: 'Excel Upload • Session Setup • Multi-Device Sync • Export Reports' },
  USER: { pass: 'user123', label: 'User (Scanner Only)', priv: 'Barcode Scanning • Stock Counting • MRP & Size Verification' }
};

// Column Schema Definition
const COLUMN_FIELDS = {
  core: [
    { key: 'ean', label: 'EAN / Barcode', required: true, keywords: ['ean', 'barcode', 'upc', 'bar_code', 'code', 'item_code'] },
    { key: 'qty', label: 'Expected Quantity', required: true, keywords: ['qty', 'quantity', 'pcs', 'count', 'expected_qty', 'total_qty', 'units', 'stock'] },
    { key: 'mrp', label: 'MRP / Tag Price', required: false, keywords: ['mrp', 'price', 'tag_mrp', 'retail_price', 'rate_mrp', 'tag_price'] },
    { key: 'size', label: 'Size', required: false, keywords: ['size', 'sz', 'garment_size', 'item_size'] }
  ],
  optional: [
    { key: 'rate', label: 'Purchase Rate / Cost', keywords: ['purchase_rate', 'pur_rate', 'cost', 'buy_price', 'unit_rate', 'rate'] },
    { key: 'brand', label: 'Brand Name', keywords: ['brand', 'company', 'label', 'make'] },
    { key: 'pattern', label: 'Pattern / Print', keywords: ['pattern', 'print', 'style_pattern'] },
    { key: 'section', label: 'Section / Department', keywords: ['section', 'sec', 'department', 'dept', 'category'] },
    { key: 'season', label: 'Season / Collection', keywords: ['season', 'collection'] },
    { key: 'design', label: 'Design Number / Style', keywords: ['design_no', 'design', 'style', 'style_no', 'article_no', 'design_num'] },
    { key: 'nature', label: 'Nature / Item Type', keywords: ['nature', 'item_type', 'item', 'description', 'desc', 'garment_type'] }
  ]
};

// ==========================================
// 1. NATIVE WEB CRYPTO AES-256-GCM ENCRYPTION
// ==========================================
async function getCryptoKey(passphrase) {
  const enc = new TextEncoder();
  const salt = enc.encode('GarmentVerifySalt2026_Secure');
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 50000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptPayload(dataObj, password = 'DefaultMasterKey2026') {
  try {
    const enc = new TextEncoder();
    const key = await getCryptoKey(password);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const jsonStr = JSON.stringify(dataObj);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(jsonStr));

    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);
    
    let binary = '';
    for (let i = 0; i < combined.byteLength; i++) {
      binary += String.fromCharCode(combined[i]);
    }
    return 'ENC:' + btoa(binary);
  } catch (err) {
    console.error('Encryption error:', err);
    return JSON.stringify(dataObj);
  }
}

async function decryptPayload(payloadStr, password = 'DefaultMasterKey2026') {
  if (!payloadStr || typeof payloadStr !== 'string') return payloadStr;
  if (!payloadStr.startsWith('ENC:')) {
    try { return JSON.parse(payloadStr); } catch (e) { return payloadStr; }
  }

  try {
    const dec = new TextDecoder();
    const key = await getCryptoKey(password);
    const base64Data = payloadStr.substring(4);
    const binary = atob(base64Data);
    const combined = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      combined[i] = binary.charCodeAt(i);
    }

    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const decryptedBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return JSON.parse(dec.decode(decryptedBuffer));
  } catch (err) {
    console.error('Decryption failed:', err);
    throw new Error('Incorrect password or corrupted encrypted data');
  }
}

// ==========================================
// 2B. CLOUD DATABASE & MULTI-DEVICE SYNC ENGINE
// ==========================================
const CloudSync = {
  getEndpoint() {
    return localStorage.getItem('garment_verify_cloud_url') || '';
  },

  async uploadSessionRecord(record) {
    if (!record || !record.id) return;
    try {
      const customUrl = this.getEndpoint();
      if (customUrl) {
        const endpoint = customUrl.replace(/\/+$/, '');
        await fetch(`${endpoint}/sessions/${record.id}.json`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(record)
        });
      } else {
        const payloadObj = { name: `garment_session_${record.id}`, data: record };
        const mapKey = `cloud_id_${record.id}`;
        const existingCloudId = localStorage.getItem(mapKey);

        if (existingCloudId) {
          await fetch(`https://api.restful-api.dev/objects/${existingCloudId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payloadObj)
          });
        } else {
          const res = await fetch(`https://api.restful-api.dev/objects`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payloadObj)
          });
          if (res.ok) {
            const data = await res.json();
            if (data && data.id) {
              localStorage.setItem(mapKey, data.id);
              await this.updateCloudIndex(record.id, data.id);
            }
          }
        }
      }
    } catch (err) {
      console.warn('Cloud session upload warning (working offline):', err);
    }
  },

  async updateCloudIndex(sessionId, cloudId) {
    try {
      let indexMap = {};
      const indexCloudId = localStorage.getItem('cloud_master_index_id');
      if (indexCloudId) {
        const getRes = await fetch(`https://api.restful-api.dev/objects/${indexCloudId}`);
        if (getRes.ok) {
          const resObj = await getRes.json();
          indexMap = (resObj && resObj.data) ? resObj.data : {};
        }
      }

      indexMap[sessionId] = cloudId;
      const indexPayload = { name: 'garment_master_index_v2', data: indexMap };

      if (indexCloudId) {
        await fetch(`https://api.restful-api.dev/objects/${indexCloudId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(indexPayload)
        });
      } else {
        const postRes = await fetch(`https://api.restful-api.dev/objects`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(indexPayload)
        });
        if (postRes.ok) {
          const postObj = await postRes.json();
          if (postObj && postObj.id) {
            localStorage.setItem('cloud_master_index_id', postObj.id);
          }
        }
      }
    } catch (e) {
      console.warn('Cloud index update error:', e);
    }
  },

  async deleteSessionFromCloud(id) {
    if (!id) return;
    try {
      const customUrl = this.getEndpoint();
      if (customUrl) {
        const endpoint = customUrl.replace(/\/+$/, '');
        await fetch(`${endpoint}/sessions/${id}.json`, { method: 'DELETE' });
      } else {
        const mapKey = `cloud_id_${id}`;
        const cloudId = localStorage.getItem(mapKey);
        if (cloudId) {
          await fetch(`https://api.restful-api.dev/objects/${cloudId}`, { method: 'DELETE' });
          localStorage.removeItem(mapKey);
        }
      }
    } catch (err) {
      console.warn('Cloud delete warning:', err);
    }
  },

  async uploadUsersToCloud(users) {
    if (!users) return;
    try {
      const customUrl = this.getEndpoint();
      if (customUrl) {
        const endpoint = customUrl.replace(/\/+$/, '');
        await fetch(`${endpoint}/system_users.json`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(users)
        });
      }
    } catch (err) {
      console.warn('Cloud users upload warning:', err);
    }
  },

  async syncAllFromCloud(silent = true) {
    if (!navigator.onLine) {
      if (!silent) showToast('Offline Mode: Loaded from Local Storage', 'warning');
      return false;
    }

    let syncedCount = 0;
    try {
      const customUrl = this.getEndpoint();
      if (customUrl) {
        const endpoint = customUrl.replace(/\/+$/, '');
        const usersRes = await fetch(`${endpoint}/system_users.json`);
        if (usersRes.ok) {
          const cloudUsers = await usersRes.json();
          if (cloudUsers && Array.isArray(cloudUsers) && cloudUsers.length > 0) {
            localStorage.setItem('garment_verify_custom_users', JSON.stringify(cloudUsers));
          }
        }

        const sessRes = await fetch(`${endpoint}/sessions.json`);
        if (sessRes.ok) {
          const cloudSessionsObj = await sessRes.json();
          if (cloudSessionsObj && typeof cloudSessionsObj === 'object') {
            const cloudSessions = Object.values(cloudSessionsObj);
            const db = await DB.open();
            for (const sRecord of cloudSessions) {
              if (sRecord && sRecord.id && sRecord.payload) {
                await new Promise((res) => {
                  const tx = db.transaction('sessions', 'readwrite');
                  const store = tx.objectStore('sessions');
                  const req = store.put(sRecord);
                  req.onsuccess = res;
                  req.onerror = res;
                });
                syncedCount++;
              }
            }
          }
        }
      } else {
        const indexCloudId = localStorage.getItem('cloud_master_index_id');
        let indexMap = {};
        if (indexCloudId) {
          const getRes = await fetch(`https://api.restful-api.dev/objects/${indexCloudId}`);
          if (getRes.ok) {
            const resObj = await getRes.json();
            indexMap = (resObj && resObj.data) ? resObj.data : {};
          }
        }

        const cloudIds = Object.values(indexMap);
        if (cloudIds.length > 0) {
          const db = await DB.open();
          for (const cId of cloudIds) {
            try {
              const fetchRes = await fetch(`https://api.restful-api.dev/objects/${cId}`);
              if (fetchRes.ok) {
                const itemObj = await fetchRes.json();
                if (itemObj && itemObj.data && itemObj.data.id && itemObj.data.payload) {
                  const sRecord = itemObj.data;
                  await new Promise((res) => {
                    const tx = db.transaction('sessions', 'readwrite');
                    const store = tx.objectStore('sessions');
                    const req = store.put(sRecord);
                    req.onsuccess = res;
                    req.onerror = res;
                  });
                  syncedCount++;
                }
              }
            } catch (err) {}
          }
        }
      }

      if (!silent) {
        showToast(`☁️ Cloud Sync Successful! ${syncedCount} session(s) updated`, 'success');
      }
      return true;
    } catch (err) {
      console.warn('Cloud sync error:', err);
      if (!silent) {
        showToast('Cloud Sync Notice: Working with Local Storage', 'warning');
      }
      return false;
    }
  }
};

// ==========================================
// 2C. GITHUB REPOSITORY AUTO-SYNC & BACKUP ENGINE
// ==========================================
const GitHubSync = {
  getConfig() {
    return {
      repo: localStorage.getItem('garment_github_repo') || '',
      branch: localStorage.getItem('garment_github_branch') || 'main',
      token: localStorage.getItem('garment_github_token') || ''
    };
  },

  setConfig(repo, branch = 'main', token = '') {
    if (repo) localStorage.setItem('garment_github_repo', repo);
    else localStorage.removeItem('garment_github_repo');

    if (branch) localStorage.setItem('garment_github_branch', branch);
    else localStorage.removeItem('garment_github_branch');

    if (token) localStorage.setItem('garment_github_token', token);
    else localStorage.removeItem('garment_github_token');
  },

  async pullFromGitHub(silent = true) {
    if (!navigator.onLine) return false;
    const config = this.getConfig();
    if (!config.repo) return false;

    try {
      const repoPath = config.repo.replace(/^\/+|\/+$/g, '');
      const rawUrl = `https://raw.githubusercontent.com/${repoPath}/${config.branch || 'main'}/sessions_db.json?t=${Date.now()}`;

      const res = await fetch(rawUrl);
      if (res.ok) {
        const dbData = await res.json();
        if (dbData && dbData.sessions && Array.isArray(dbData.sessions)) {
          const db = await DB.open();
          for (const sRecord of dbData.sessions) {
            if (sRecord && sRecord.id && sRecord.payload) {
              await new Promise((resolve) => {
                const tx = db.transaction('sessions', 'readwrite');
                const store = tx.objectStore('sessions');
                const req = store.put(sRecord);
                req.onsuccess = resolve;
                req.onerror = resolve;
              });
            }
          }

          if (dbData.users && Array.isArray(dbData.users) && dbData.users.length > 0) {
            localStorage.setItem('garment_verify_custom_users', JSON.stringify(dbData.users));
          }

          if (!silent) {
            showToast(`🐙 GitHub Sync: Pulled ${dbData.sessions.length} session(s) from repo!`, 'success');
          }
          return true;
        }
      }
    } catch (err) {
      console.warn('GitHub Pull error:', err);
      if (!silent) showToast('GitHub Pull: Could not fetch sessions_db.json from repo', 'warning');
    }
    return false;
  },

  async pushToGitHub(silent = true) {
    if (!navigator.onLine) return false;
    const config = this.getConfig();
    if (!config.repo || !config.token) return false;

    try {
      const repoPath = config.repo.replace(/^\/+|\/+$/g, '');
      const allSessions = await DB.getAllSessions();
      const allUsers = getSystemUsers();

      const dbData = {
        app: 'GarmentVerify',
        updatedAt: new Date().toISOString(),
        sessions: allSessions,
        users: allUsers
      };

      const jsonStr = JSON.stringify(dbData, null, 2);
      const contentBase64 = btoa(unescape(encodeURIComponent(jsonStr)));
      const apiUrl = `https://api.github.com/repos/${repoPath}/contents/sessions_db.json`;

      let sha = '';
      try {
        const getRes = await fetch(apiUrl, {
          headers: {
            'Authorization': `token ${config.token}`,
            'Accept': 'application/vnd.github.v3+json'
          }
        });
        if (getRes.ok) {
          const fileObj = await getRes.json();
          sha = fileObj.sha || '';
        }
      } catch (e) {}

      const bodyPayload = {
        message: `Auto-Backup Sessions DB: ${new Date().toLocaleString()}`,
        content: contentBase64,
        branch: config.branch || 'main'
      };
      if (sha) bodyPayload.sha = sha;

      const putRes = await fetch(apiUrl, {
        method: 'PUT',
        headers: {
          'Authorization': `token ${config.token}`,
          'Content-Type': 'application/json',
          'Accept': 'application/vnd.github.v3+json'
        },
        body: JSON.stringify(bodyPayload)
      });

      if (putRes.ok) {
        if (!silent) showToast('🐙 GitHub Auto-Backup: Committed sessions_db.json to repository!', 'success');
        return true;
      }
    } catch (err) {
      console.warn('GitHub Push error:', err);
    }
    return false;
  },

  async exportDbJsonFile() {
    const allSessions = await DB.getAllSessions();
    const allUsers = getSystemUsers();

    const dbData = {
      app: 'GarmentVerify',
      updatedAt: new Date().toISOString(),
      sessions: allSessions,
      users: allUsers
    };

    const jsonStr = JSON.stringify(dbData, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sessions_db.json';
    a.click();
    URL.revokeObjectURL(url);
    showToast('Downloaded sessions_db.json for your GitHub repo!', 'success');
  }
};

// ==========================================
// 2. INDEXEDDB PERSISTENCE MODULE (ENCRYPTED)
// ==========================================
const DB = {
  dbName: 'GarmentVerifyDB_V2',
  dbVersion: 1,

  open() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.dbVersion);
      request.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('sessions')) {
          db.createObjectStore('sessions', { keyPath: 'id' });
        }
      };
      request.onsuccess = (e) => resolve(e.target.result);
      request.onerror = (e) => reject(e.target.error);
    });
  },

  async saveSession(session) {
    try {
      const db = await this.open();
      const pass = state.currentUser ? state.currentUser.passcode : 'DefaultMasterKey2026';
      session.updatedAt = new Date().toISOString();
      session.lastUpdatedBy = state.currentUser ? state.currentUser.name : 'System';

      const encryptedData = await encryptPayload(session, pass);
      const record = { id: session.id, payload: encryptedData, updatedAt: session.updatedAt, supplierName: session.supplierName, invoiceNo: session.invoiceNo };

      return new Promise((resolve, reject) => {
        const tx = db.transaction('sessions', 'readwrite');
        const store = tx.objectStore('sessions');
        const req = store.put(record);
        req.onsuccess = () => {
          CloudSync.uploadSessionRecord(record);
          resolve(session);
        };
        req.onerror = (e) => reject(e.target.error);
      });
    } catch (err) {
      console.error('Failed to save session:', err);
      showToast('Warning: Session auto-save failed', 'warning');
    }
  },

  async getSession(id) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('sessions', 'readonly');
      const store = tx.objectStore('sessions');
      const req = store.get(id);
      req.onsuccess = async () => {
        if (!req.result) return resolve(null);
        try {
          const pass = state.currentUser ? state.currentUser.passcode : 'DefaultMasterKey2026';
          const decrypted = await decryptPayload(req.result.payload, pass);
          resolve(decrypted);
        } catch (e) {
          reject(e);
        }
      };
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async getAllSessions() {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('sessions', 'readonly');
      const store = tx.objectStore('sessions');
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async deleteSession(id) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('sessions', 'readwrite');
      const store = tx.objectStore('sessions');
      const req = store.delete(id);
      req.onsuccess = () => {
        CloudSync.deleteSessionFromCloud(id);
        resolve();
      };
      req.onerror = (e) => reject(e.target.error);
    });
  }
};

// ==========================================
// 3. ROLE AUTHENTICATION & USER MANAGEMENT ENGINE
// ==========================================

function getSystemUsers() {
  const saved = localStorage.getItem('garment_verify_custom_users');
  if (saved) {
    try { return JSON.parse(saved); } catch (e) { console.warn(e); }
  }
  return [
    { id: 'usr_admin', name: 'Ramesh Admin', role: 'ADMIN', pass: 'admin123' },
    { id: 'usr_mgr', name: 'Sunil Manager', role: 'MANAGER', pass: 'mgr123' },
    { id: 'usr_op1', name: 'Operator 1', role: 'USER', pass: 'user123' }
  ];
}

function saveSystemUsers(users) {
  localStorage.setItem('garment_verify_custom_users', JSON.stringify(users));
  renderUserManagementList();
  CloudSync.uploadUsersToCloud(users);
}

function renderUserManagementList() {
  const users = getSystemUsers();
  const tbody = document.getElementById('tbody-system-users');
  const countBadge = document.getElementById('count-system-users');

  if (countBadge) countBadge.textContent = `${users.length} Account${users.length === 1 ? '' : 's'}`;
  if (!tbody) return;

  tbody.innerHTML = users.map(u => `
    <tr>
      <td><strong>${u.name}</strong></td>
      <td>
        <span class="badge ${u.role === 'ADMIN' ? 'badge-danger' : u.role === 'MANAGER' ? 'badge-info' : 'badge-success'}">
          ${u.role === 'USER' ? '📱 OPERATOR' : u.role === 'MANAGER' ? '👔 MANAGER' : '👑 ADMIN'}
        </span>
      </td>
      <td><code>${u.pass}</code></td>
      <td>
        ${u.role === 'ADMIN' && users.filter(x => x.role === 'ADMIN').length <= 1 ? 
          '<span class="text-muted" style="font-size:0.8rem;">Master Admin</span>' : 
          `<button type="button" class="btn btn-sm btn-outline btn-delete-user" data-id="${u.id}">Delete</button>`
        }
      </td>
    </tr>
  `).join('');

  tbody.querySelectorAll('.btn-delete-user').forEach(btn => {
    btn.onclick = () => {
      const userId = btn.getAttribute('data-id');
      deleteSystemUser(userId);
    };
  });
}

function createSystemUser(name, role, pass) {
  const users = getSystemUsers();
  if (users.some(u => u.name.toLowerCase() === name.toLowerCase())) {
    showToast(`User '${name}' already exists!`, 'warning');
    return false;
  }
  const newUser = {
    id: `usr_${Date.now()}`,
    name,
    role,
    pass
  };
  users.push(newUser);
  saveSystemUsers(users);
  showToast(`Account created for ${role}: ${name}`, 'success');
  return true;
}

function deleteSystemUser(userId) {
  let users = getSystemUsers();
  const target = users.find(u => u.id === userId);
  if (!target) return;

  if (confirm(`Delete account for '${target.name}'?`)) {
    users = users.filter(u => u.id !== userId);
    saveSystemUsers(users);
    showToast(`Account '${target.name}' deleted`, 'info');
  }
}

// Role tab selector & privilege description updater
function selectLoginRole(selectedRole) {
  document.querySelectorAll('.btn-role-tab').forEach(b => b.classList.remove('active'));
  const activeTab = document.querySelector(`.btn-role-tab[data-role="${selectedRole}"]`);
  if (activeTab) activeTab.classList.add('active');

  document.getElementById('input-login-role').value = selectedRole;

  const roleInfo = ROLE_CREDENTIALS[selectedRole] || ROLE_CREDENTIALS.ADMIN;
  const privilegeText = document.getElementById('role-privilege-text');
  const privilegeCard = document.getElementById('role-privilege-card');

  if (privilegeText) privilegeText.textContent = roleInfo.priv;
  if (privilegeCard) {
    privilegeCard.querySelector('.privilege-title').textContent = `${selectedRole} PRIVILEGES:`;
  }
}

document.querySelectorAll('.btn-role-tab').forEach(btn => {
  btn.addEventListener('click', () => {
    const role = btn.getAttribute('data-role');
    selectLoginRole(role);
  });
});

// Quick Passcode Auto-Fill Pills
document.querySelectorAll('.btn-autofill').forEach(btn => {
  btn.addEventListener('click', () => {
    const role = btn.getAttribute('data-role');
    const pass = btn.getAttribute('data-pass');
    selectLoginRole(role);
    document.getElementById('input-login-password').value = pass;

    if (role === 'ADMIN') document.getElementById('input-login-name').value = 'Ramesh Admin';
    if (role === 'MANAGER') document.getElementById('input-login-name').value = 'Sunil Manager';
    if (role === 'USER') document.getElementById('input-login-name').value = 'Operator 1';

    showToast(`Auto-filled credentials for ${role}`, 'info');
  });
});

// Toggle Show/Hide Password
document.getElementById('btn-toggle-password')?.addEventListener('click', () => {
  const pwInput = document.getElementById('input-login-password');
  if (pwInput.type === 'password') {
    pwInput.type = 'text';
    document.getElementById('btn-toggle-password').textContent = '🙈';
  } else {
    pwInput.type = 'password';
    document.getElementById('btn-toggle-password').textContent = '👁️';
  }
});

document.getElementById('form-login').addEventListener('submit', (e) => {
  e.preventDefault();
  const role = document.getElementById('input-login-role').value;
  const nameInput = document.getElementById('input-login-name').value.trim();
  const pass = document.getElementById('input-login-password').value.trim();
  const remember = document.getElementById('chk-remember-me').checked;

  const systemUsers = getSystemUsers();
  const matchedUser = systemUsers.find(u => u.role === role && u.pass === pass);
  const defaultPass = ROLE_CREDENTIALS[role] ? ROLE_CREDENTIALS[role].pass : 'admin123';

  if (!matchedUser && pass !== defaultPass) {
    showToast(`Invalid password for ${role}!`, 'error');
    return;
  }

  const finalName = nameInput || (matchedUser ? matchedUser.name : `${role} User`);
  state.currentUser = { role, name: finalName, passcode: pass, loginTime: new Date().toISOString() };

  if (remember) {
    localStorage.setItem('garment_verify_auth', JSON.stringify(state.currentUser));
  } else {
    sessionStorage.setItem('garment_verify_auth', JSON.stringify(state.currentUser));
  }

  document.getElementById('modal-login').classList.add('hidden');
  applyRolePermissions();
  renderSavedSessionsList();
  showToast(`Logged in as ${role}: ${finalName}`, 'success');
});

document.getElementById('btn-lock-app').addEventListener('click', () => {
  if (confirm('Lock session & switch user role?')) {
    localStorage.removeItem('garment_verify_auth');
    sessionStorage.removeItem('garment_verify_auth');
    state.currentUser = null;
    document.getElementById('modal-login').classList.remove('hidden');
    showToast('App Locked', 'info');
  }
});

// Admin Rights Management Modal Event Bindings
document.getElementById('btn-admin-manage-users')?.addEventListener('click', () => {
  if (state.currentUser?.role !== 'ADMIN') {
    showToast('Admin permission required', 'error');
    return;
  }
  renderUserManagementList();
  document.getElementById('modal-user-management').classList.remove('hidden');
});

document.getElementById('btn-close-user-modal')?.addEventListener('click', () => {
  document.getElementById('modal-user-management').classList.add('hidden');
});

document.getElementById('form-create-user')?.addEventListener('submit', (e) => {
  e.preventDefault();
  const name = document.getElementById('input-new-user-name').value.trim();
  const role = document.getElementById('select-new-user-role').value;
  const pass = document.getElementById('input-new-user-pass').value.trim();

  if (createSystemUser(name, role, pass)) {
    document.getElementById('form-create-user').reset();
  }
});

function checkAuthOnLoad() {
  const saved = localStorage.getItem('garment_verify_auth') || sessionStorage.getItem('garment_verify_auth');
  if (saved) {
    try {
      state.currentUser = JSON.parse(saved);
      document.getElementById('modal-login').classList.add('hidden');
      applyRolePermissions();
      return;
    } catch (e) { console.warn(e); }
  }
  document.getElementById('modal-login').classList.remove('hidden');
}

function applyRolePermissions() {
  if (!state.currentUser) return;

  const role = state.currentUser.role;
  const name = state.currentUser.name;

  const roleBadge = document.getElementById('user-role-badge');
  roleBadge.textContent = role;
  roleBadge.className = `badge ${role === 'ADMIN' ? 'badge-danger' : role === 'MANAGER' ? 'badge-info' : 'badge-success'}`;

  document.getElementById('user-name-display').textContent = name;
  document.getElementById('scanner-active-user-badge').textContent = `Scanner: ${name}`;

  const cardNewSession = document.getElementById('card-new-session');
  const adminDeleteBox = document.getElementById('admin-delete-session-box');
  const btnAdminRights = document.getElementById('btn-admin-manage-users');

  if (role === 'USER') {
    if (btnAdminRights) btnAdminRights.classList.add('hidden');
    if (cardNewSession) cardNewSession.classList.add('hidden');
    if (adminDeleteBox) adminDeleteBox.classList.add('hidden');
    document.getElementById('nav-mapping-btn')?.classList.add('hidden');
    document.getElementById('nav-setup-btn')?.classList.add('hidden');
  } else if (role === 'MANAGER') {
    if (btnAdminRights) btnAdminRights.classList.add('hidden');
    if (cardNewSession) cardNewSession.classList.remove('hidden');
    if (adminDeleteBox) adminDeleteBox.classList.add('hidden');
  } else if (role === 'ADMIN') {
    if (btnAdminRights) btnAdminRights.classList.remove('hidden');
    if (cardNewSession) cardNewSession.classList.remove('hidden');
    if (adminDeleteBox) adminDeleteBox.classList.remove('hidden');
  }
}

// ==========================================
// 4. AUDIO & VIBRATION FEEDBACK MODULE
// ==========================================
function playBeep(type = 'success') {
  if (!state.currentSession?.settings?.soundEnabled) return;
  try {
    if (!state.audioCtx) {
      state.audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
    const ctx = state.audioCtx;
    if (ctx.state === 'suspended') ctx.resume();

    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);

    if (type === 'success') {
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      gain.gain.setValueAtTime(0.15, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.12);
      osc.start();
      osc.stop(ctx.currentTime + 0.12);
    } else if (type === 'warning') {
      osc.frequency.setValueAtTime(587.33, ctx.currentTime);
      osc.frequency.setValueAtTime(440, ctx.currentTime + 0.1);
      gain.gain.setValueAtTime(0.2, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.25);
      osc.start();
      osc.stop(ctx.currentTime + 0.25);
    } else if (type === 'error') {
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(220, ctx.currentTime);
      gain.gain.setValueAtTime(0.25, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.35);
      osc.start();
      osc.stop(ctx.currentTime + 0.35);
    }
  } catch (e) { console.warn('Audio error:', e); }

  if (state.currentSession?.settings?.vibrateEnabled && navigator.vibrate) {
    if (type === 'success') navigator.vibrate(60);
    else if (type === 'warning') navigator.vibrate([100, 50, 100]);
    else if (type === 'error') navigator.vibrate([200, 100, 200]);
  }
}

// ==========================================
// 5. UI ROUTER & NAVIGATION MODULE
// ==========================================
function switchView(viewId) {
  document.querySelectorAll('.view-panel').forEach(panel => panel.classList.remove('active'));
  document.querySelectorAll('.nav-btn, .mobile-nav-btn').forEach(btn => btn.classList.remove('active'));

  const targetPanel = document.getElementById(`view-${viewId}`);
  const targetNavBtns = document.querySelectorAll(`[data-view="${viewId}"]`);

  if (targetPanel) targetPanel.classList.add('active');
  targetNavBtns.forEach(btn => btn.classList.add('active'));

  if (viewId === 'scan') {
    setTimeout(() => {
      const input = document.getElementById('input-barcode-scan');
      if (input) input.focus();
    }, 150);
  }

  if (viewId === 'overview') renderInventoryOverview();
  if (viewId === 'export') renderExportReview();
}

function updateNavPill() {
  const pill = document.getElementById('active-session-pill');
  const desktopBtns = ['nav-mapping-btn', 'nav-setup-btn', 'nav-scan-btn', 'nav-overview-btn', 'nav-export-btn'];
  const mobileBtns = ['mobile-nav-mapping-btn', 'mobile-nav-scan-btn', 'mobile-nav-overview-btn', 'mobile-nav-export-btn'];

  if (state.currentSession) {
    pill.classList.remove('hidden');
    document.getElementById('nav-supplier-name').textContent = state.currentSession.supplierName;
    document.getElementById('nav-invoice-no').textContent = state.currentSession.invoiceNo;
    desktopBtns.forEach(id => document.getElementById(id)?.classList.remove('hidden'));
    mobileBtns.forEach(id => document.getElementById(id)?.classList.remove('hidden'));
  } else {
    pill.classList.add('hidden');
    desktopBtns.forEach(id => document.getElementById(id)?.classList.add('hidden'));
    mobileBtns.forEach(id => document.getElementById(id)?.classList.add('hidden'));
  }
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 3200);
}

// ==========================================
// 6. EXCEL IMPORT & COLUMN MAPPING ENGINE
// ==========================================
document.getElementById('input-excel-file').addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (file) {
    document.getElementById('file-name-display').textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
  }
});

document.getElementById('form-new-session').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (state.currentUser?.role === 'USER') {
    showToast('Users cannot create new sessions. Manager or Admin access required.', 'error');
    return;
  }

  const supplierName = document.getElementById('input-supplier').value.trim();
  const invoiceNo = document.getElementById('input-invoice').value.trim();
  const date = document.getElementById('input-date').value;
  const fileInput = document.getElementById('input-excel-file');

  if (!fileInput.files || fileInput.files.length === 0) {
    showToast('Please select a valid Excel file', 'error');
    return;
  }

  const file = fileInput.files[0];
  const reader = new FileReader();

  reader.onload = (evt) => {
    try {
      const data = new Uint8Array(evt.target.result);
      const workbook = XLSX.read(data, { type: 'array' });
      const firstSheetName = workbook.SheetNames[0];
      const worksheet = workbook.Sheets[firstSheetName];
      const jsonRows = XLSX.utils.sheet_to_json(worksheet, { header: 1, defval: '' });

      if (jsonRows.length < 2) {
        showToast('Excel file contains no data rows', 'error');
        return;
      }

      state.excelRawData = jsonRows;
      state.excelHeaders = jsonRows[0].map(h => String(h).trim());
      state.excelRows = jsonRows.slice(1).filter(row => row.some(cell => String(cell).trim() !== ''));

      state.currentSession = {
        id: `session_${Date.now()}`,
        supplierName,
        invoiceNo,
        verificationDate: date,
        fileName: file.name,
        createdBy: state.currentUser ? state.currentUser.name : 'Manager',
        excelHeaders: state.excelHeaders,
        excelRawData: state.excelRawData,
        columnMapping: {},
        verificationFields: { mrp: true, qty: true, size: true, brand: false, design: false, nature: false },
        settings: { soundEnabled: true, vibrateEnabled: true },
        items: [],
        extraStock: [],
        scanHistory: []
      };

      renderColumnMappingUI();
      autoSuggestMapping();
      updateNavPill();
      switchView('mapping');
      showToast('Excel uploaded & encrypted successfully', 'success');

    } catch (err) {
      console.error('Excel parse error:', err);
      showToast('Failed to parse Excel file', 'error');
    }
  };

  reader.readAsArrayBuffer(file);
});

function renderColumnMappingUI() {
  document.getElementById('mapping-file-meta').textContent = 
    `File: ${state.currentSession.fileName} | Rows: ${state.excelRows.length} | Columns: ${state.excelHeaders.length}`;

  const renderGrid = (fields, containerId) => {
    const container = document.getElementById(containerId);
    container.innerHTML = fields.map(field => `
      <div class="mapping-item">
        <label class="mapping-label">
          <span>${field.label} ${field.required ? '<span class="required">*</span>' : ''}</span>
        </label>
        <select class="column-select" data-field="${field.key}" ${field.required ? 'required' : ''}>
          <option value="">-- Select Excel Header --</option>
          ${state.excelHeaders.map((hdr, idx) => `<option value="${idx}">${hdr}</option>`).join('')}
        </select>
      </div>
    `).join('');
  };

  renderGrid(COLUMN_FIELDS.core, 'core-mapping-grid');
  renderGrid(COLUMN_FIELDS.optional, 'optional-mapping-grid');

  document.querySelectorAll('.column-select').forEach(sel => {
    sel.addEventListener('change', () => {
      saveMappingFromUI();
      renderMappingPreviewAndWarnings();
    });
  });
}

function autoSuggestMapping() {
  const allFields = [...COLUMN_FIELDS.core, ...COLUMN_FIELDS.optional];
  const selects = document.querySelectorAll('.column-select');

  selects.forEach(select => {
    const fieldKey = select.getAttribute('data-field');
    const fieldDef = allFields.find(f => f.key === fieldKey);
    if (!fieldDef) return;

    let bestMatchIdx = -1;
    state.excelHeaders.forEach((hdr, idx) => {
      const cleanHdr = hdr.toLowerCase().replace(/[^a-z0-9_]/g, '');
      if (fieldDef.keywords.some(kw => cleanHdr.includes(kw))) {
        if (bestMatchIdx === -1) bestMatchIdx = idx;
      }
    });

    if (bestMatchIdx !== -1) {
      select.value = String(bestMatchIdx);
    }
  });

  saveMappingFromUI();
  renderMappingPreviewAndWarnings();
}

document.getElementById('btn-auto-map').addEventListener('click', autoSuggestMapping);

function saveMappingFromUI() {
  const mapping = {};
  document.querySelectorAll('.column-select').forEach(select => {
    const key = select.getAttribute('data-field');
    const val = select.value;
    if (val !== '') {
      mapping[key] = parseInt(val, 10);
    }
  });
  state.currentSession.columnMapping = mapping;
}

function renderMappingPreviewAndWarnings() {
  const mapping = state.currentSession.columnMapping;
  const eanIdx = mapping.ean;
  const qtyIdx = mapping.qty;

  const warnings = [];
  if (eanIdx === undefined) warnings.push('EAN / Barcode column is not mapped.');
  if (qtyIdx === undefined) warnings.push('Expected Quantity column is not mapped.');

  if (eanIdx !== undefined && qtyIdx !== undefined) {
    let emptyEanCount = 0;
    let invalidQtyCount = 0;
    const eanSet = new Set();
    const duplicateEans = new Set();

    state.excelRows.forEach((row) => {
      const eanVal = String(row[eanIdx] || '').trim();
      const qtyVal = parseFloat(row[qtyIdx]);

      if (!eanVal) emptyEanCount++;
      if (isNaN(qtyVal) || qtyVal < 0) invalidQtyCount++;

      if (eanVal) {
        if (eanSet.has(eanVal)) duplicateEans.add(eanVal);
        else eanSet.add(eanVal);
      }
    });

    if (emptyEanCount > 0) warnings.push(`${emptyEanCount} rows missing EAN barcode.`);
    if (invalidQtyCount > 0) warnings.push(`${invalidQtyCount} rows have invalid quantity.`);
    if (duplicateEans.size > 0) warnings.push(`${duplicateEans.size} duplicate EAN codes detected across sizes. Safe duplicate handler will prompt.`);
  }

  const warningsBox = document.getElementById('mapping-warnings-box');
  const warningsList = document.getElementById('mapping-warnings-list');

  if (warnings.length > 0) {
    warningsBox.classList.remove('hidden');
    warningsList.innerHTML = warnings.map(w => `<li>${w}</li>`).join('');
  } else {
    warningsBox.classList.add('hidden');
  }

  const theadRow = document.getElementById('preview-thead-row');
  const tbody = document.getElementById('preview-tbody');

  theadRow.innerHTML = state.excelHeaders.map((hdr, i) => {
    const mappedKey = Object.keys(mapping).find(k => mapping[k] === i);
    return `<th>${hdr} ${mappedKey ? `<br><small class="badge badge-info">${mappedKey.toUpperCase()}</small>` : ''}</th>`;
  }).join('');

  const sampleRows = state.excelRows.slice(0, 5);
  tbody.innerHTML = sampleRows.map(row => `
    <tr>
      ${state.excelHeaders.map((_, i) => `<td>${row[i] !== undefined ? row[i] : ''}</td>`).join('')}
    </tr>
  `).join('');
}

document.getElementById('btn-back-to-dashboard').addEventListener('click', () => switchView('dashboard'));
document.getElementById('btn-proceed-to-setup').addEventListener('click', () => {
  saveMappingFromUI();
  const mapping = state.currentSession.columnMapping;
  if (mapping.ean === undefined || mapping.qty === undefined) {
    showToast('Please map EAN / Barcode and Expected Quantity before proceeding', 'error');
    return;
  }
  buildSessionItemsFromMapping();
  switchView('setup');
});

function buildSessionItemsFromMapping() {
  const m = state.currentSession.columnMapping;
  
  state.currentSession.items = state.excelRows.map((row, idx) => {
    const rawEan = String(row[m.ean] || '').trim();
    const rawQty = parseFloat(row[m.qty]) || 0;
    const rawMrp = m.mrp !== undefined ? (parseFloat(row[m.mrp]) || 0) : 0;
    const rawSize = m.size !== undefined ? String(row[m.size] || '').trim() : '';

    return {
      rowIndex: idx + 1,
      ean: rawEan,
      expectedQty: rawQty,
      scannedQty: 0,
      actualPhysicalQty: 0,
      expectedMrp: rawMrp,
      actualMrp: rawMrp,
      mrpStatus: 'Not Verified',
      expectedSize: rawSize,
      actualSize: rawSize,
      sizeStatus: 'Not Verified',
      rate: m.rate !== undefined ? (parseFloat(row[m.rate]) || 0) : 0,
      brand: m.brand !== undefined ? String(row[m.brand] || '').trim() : '',
      pattern: m.pattern !== undefined ? String(row[m.pattern] || '').trim() : '',
      section: m.section !== undefined ? String(row[m.section] || '').trim() : '',
      season: m.season !== undefined ? String(row[m.season] || '').trim() : '',
      design: m.design !== undefined ? String(row[m.design] || '').trim() : '',
      nature: m.nature !== undefined ? String(row[m.nature] || '').trim() : '',
      scannedBy: '',
      remarks: '',
      rawRowData: row
    };
  });

  DB.saveSession(state.currentSession);
}

// ==========================================
// 7. VERIFICATION SETUP ENGINE
// ==========================================
document.getElementById('btn-back-to-mapping').addEventListener('click', () => switchView('mapping'));
document.getElementById('btn-start-scanning').addEventListener('click', () => {
  state.currentSession.verificationFields = {
    mrp: document.getElementById('chk-verify-mrp').checked,
    qty: true,
    size: document.getElementById('chk-verify-size').checked,
    brand: document.getElementById('chk-verify-brand').checked,
    design: document.getElementById('chk-verify-design').checked,
    nature: document.getElementById('chk-verify-nature').checked
  };

  state.currentSession.settings = {
    soundEnabled: document.getElementById('chk-sound-enabled').checked,
    vibrateEnabled: document.getElementById('chk-vibrate-enabled').checked
  };

  DB.saveSession(state.currentSession);
  updateScanViewSummary();
  switchView('scan');
});

// ==========================================
// 8. SCAN & VERIFY OPERATIONAL MODULE
// ==========================================
const scanInput = document.getElementById('input-barcode-scan');
const clearInputBtn = document.getElementById('btn-clear-scan-input');

scanInput.addEventListener('input', () => {
  if (scanInput.value.length > 0) clearInputBtn.classList.remove('hidden');
  else clearInputBtn.classList.add('hidden');
});

clearInputBtn.addEventListener('click', () => {
  scanInput.value = '';
  clearInputBtn.classList.add('hidden');
  scanInput.focus();
});

document.getElementById('form-scan-barcode').addEventListener('submit', (e) => {
  e.preventDefault();
  const code = scanInput.value.trim();
  if (code) {
    handleBarcodeScan(code);
    scanInput.value = '';
    clearInputBtn.classList.add('hidden');
    scanInput.focus();
  }
});

function handleBarcodeScan(scannedCode) {
  if (!state.currentSession || !state.currentSession.items) return;

  if (state.isScanLocked) {
    playBeep('warning');
    showToast('⚠️ Scan Locked! Please click "CONFIRM & SCAN NEXT ITEM" to verify current item.', 'warning');
    const confirmBtn = document.getElementById('btn-confirm-next-scan');
    if (confirmBtn) {
      confirmBtn.scrollIntoView({ behavior: 'smooth', block: 'center' });
      confirmBtn.focus();
    }
    return;
  }

  // Auto-close camera scanner if active to prevent continuous multi-scanning
  if (state.isScanningCamera) {
    stopCameraScanner();
    document.getElementById('modal-camera-scanner')?.classList.add('hidden');
  }

  const codeStr = String(scannedCode).trim();
  const matchingItems = state.currentSession.items.filter(item => 
    item.ean.toLowerCase() === codeStr.toLowerCase()
  );

  if (matchingItems.length === 0) {
    const extraMatch = state.currentSession.extraStock.find(item => item.ean.toLowerCase() === codeStr.toLowerCase());
    if (extraMatch) {
      state.isScanLocked = true;
      displayProductCard(extraMatch, true);
      playBeep('success');
      showToast(`Extra Item Scanned: ${codeStr}`, 'info');
      return;
    }

    playBeep('error');
    if (confirm(`Item EAN '${codeStr}' not found in Excel sheet!\n\nAdd as Extra / Unlisted Stock?`)) {
      openExtraStockModal(codeStr);
    }
    return;
  }

  if (matchingItems.length === 1) {
    executeScanForItem(matchingItems[0]);
  } else {
    playBeep('warning');
    openDuplicateEanModal(codeStr, matchingItems);
  }
}

function executeScanForItem(item) {
  state.isScanLocked = true; // Lock scanning until current item is verified & confirmed!
  item.scannedQty += 1;
  const userName = state.currentUser ? state.currentUser.name : 'Operator';
  item.scannedBy = userName;

  if (item.actualPhysicalQty === (item.scannedQty - 1)) {
    item.actualPhysicalQty = item.scannedQty;
  }

  const scanRecord = {
    timestamp: new Date().toISOString(),
    ean: item.ean,
    rowIndex: item.rowIndex,
    scannedBy: userName,
    type: 'excel'
  };

  state.currentSession.scanHistory.push(scanRecord);

  const isExcess = item.scannedQty > item.expectedQty;
  playBeep(isExcess ? 'warning' : 'success');

  state.activeScanItem = item;
  displayProductCard(item, false);
  updateScanViewSummary();
  DB.saveSession(state.currentSession);

  broadcastScanToPeers(scanRecord);
}

function displayProductCard(item, isExtra = false) {
  document.getElementById('scan-empty-state').classList.add('hidden');
  document.getElementById('scan-product-content').classList.remove('hidden');

  document.getElementById('product-status-badge').className = `badge ${isExtra ? 'badge-danger' : 'badge-success'}`;
  document.getElementById('product-status-badge').textContent = isExtra ? 'UNLISTED EXTRA PRODUCT' : 'LISTED EXCEL ITEM';
  document.getElementById('product-title').textContent = `${item.brand || 'Item'} - ${item.nature || 'Garment'} (${item.design || 'Style N/A'})`;
  document.getElementById('product-ean').textContent = item.ean;
  document.getElementById('product-row-num').textContent = isExtra ? 'N/A' : `#${item.rowIndex}`;
  document.getElementById('val-scanned-by').textContent = item.scannedBy || 'System';

  document.getElementById('val-brand').textContent = item.brand || '-';
  document.getElementById('val-nature').textContent = item.nature || '-';
  document.getElementById('val-design').textContent = item.design || '-';
  document.getElementById('val-pattern').textContent = item.pattern || '-';
  document.getElementById('val-section').textContent = item.section || '-';
  document.getElementById('val-season').textContent = item.season || '-';
  document.getElementById('val-rate').textContent = item.rate ? `₹${item.rate.toFixed(2)}` : '-';

  const remaining = Math.max(0, item.expectedQty - item.scannedQty);
  const excess = Math.max(0, item.actualPhysicalQty - item.expectedQty);

  document.getElementById('qty-expected').textContent = item.expectedQty || 0;
  document.getElementById('qty-scanned').textContent = item.scannedQty;
  document.getElementById('qty-remaining').textContent = remaining;
  document.getElementById('qty-excess').textContent = excess;

  document.getElementById('input-physical-qty').value = item.actualPhysicalQty;

  const qtyStatusBadge = document.getElementById('qty-status-badge');
  const excessBanner = document.getElementById('excess-alert-banner');

  if (item.scannedQty > item.expectedQty) {
    qtyStatusBadge.className = 'qty-status-badge badge badge-danger';
    qtyStatusBadge.textContent = 'EXCESS STOCK';
    excessBanner.classList.remove('hidden');
  } else if (item.scannedQty === item.expectedQty) {
    qtyStatusBadge.className = 'qty-status-badge badge badge-success';
    qtyStatusBadge.textContent = 'MATCHED';
    excessBanner.classList.add('hidden');
  } else {
    qtyStatusBadge.className = 'qty-status-badge badge badge-warning';
    qtyStatusBadge.textContent = 'PENDING';
    excessBanner.classList.add('hidden');
  }

  const boxMrp = document.getElementById('box-mrp-verify');
  const fieldsConfig = state.currentSession.verificationFields || {};
  if (fieldsConfig.mrp !== false) {
    boxMrp.classList.remove('hidden');
    document.getElementById('mrp-expected-val').textContent = `₹${(item.expectedMrp || 0).toFixed(2)}`;
    renderMrpVerifyButtons(item);
  } else {
    boxMrp.classList.add('hidden');
  }

  const boxSize = document.getElementById('box-size-verify');
  if (fieldsConfig.size !== false) {
    boxSize.classList.remove('hidden');
    document.getElementById('size-expected-val').textContent = item.expectedSize || 'Unspecified';
    renderSizeVerifyButtons(item);
  } else {
    boxSize.classList.add('hidden');
  }

  const remarksInput = document.getElementById('input-item-remarks');
  remarksInput.value = item.remarks || '';
  remarksInput.onchange = () => {
    item.remarks = remarksInput.value;
    DB.saveSession(state.currentSession);
  };
}

function renderMrpVerifyButtons(item) {
  const btnMatch = document.getElementById('btn-mrp-match');
  const btnDiff = document.getElementById('btn-mrp-diff');
  const groupDiff = document.getElementById('group-mrp-diff');
  const inputActualMrp = document.getElementById('input-actual-mrp');

  btnMatch.className = `btn-toggle ${item.mrpStatus === 'Match' ? 'active-match' : ''}`;
  btnDiff.className = `btn-toggle ${item.mrpStatus === 'Mismatch' ? 'active-diff' : ''}`;

  if (item.mrpStatus === 'Mismatch') {
    groupDiff.classList.remove('hidden');
    inputActualMrp.value = item.actualMrp || '';
  } else {
    groupDiff.classList.add('hidden');
  }

  btnMatch.onclick = () => {
    item.mrpStatus = 'Match';
    item.actualMrp = item.expectedMrp;
    renderMrpVerifyButtons(item);
    updateScanViewSummary();
    DB.saveSession(state.currentSession);
  };

  btnDiff.onclick = () => {
    item.mrpStatus = 'Mismatch';
    renderMrpVerifyButtons(item);
    inputActualMrp.focus();
    updateScanViewSummary();
    DB.saveSession(state.currentSession);
  };

  inputActualMrp.onchange = () => {
    item.actualMrp = parseFloat(inputActualMrp.value) || 0;
    DB.saveSession(state.currentSession);
  };
}

function renderSizeVerifyButtons(item) {
  const btnMatch = document.getElementById('btn-size-match');
  const btnDiff = document.getElementById('btn-size-diff');
  const groupDiff = document.getElementById('group-size-diff');
  const inputActualSize = document.getElementById('input-actual-size');

  btnMatch.className = `btn-toggle ${item.sizeStatus === 'Match' ? 'active-match' : ''}`;
  btnDiff.className = `btn-toggle ${item.sizeStatus === 'Mismatch' ? 'active-diff' : ''}`;

  if (item.sizeStatus === 'Mismatch') {
    groupDiff.classList.remove('hidden');
    inputActualSize.value = item.actualSize || '';
  } else {
    groupDiff.classList.add('hidden');
  }

  btnMatch.onclick = () => {
    item.sizeStatus = 'Match';
    item.actualSize = item.expectedSize;
    renderSizeVerifyButtons(item);
    updateScanViewSummary();
    DB.saveSession(state.currentSession);
  };

  btnDiff.onclick = () => {
    item.sizeStatus = 'Mismatch';
    renderSizeVerifyButtons(item);
    inputActualSize.focus();
    updateScanViewSummary();
    DB.saveSession(state.currentSession);
  };

  inputActualSize.onchange = () => {
    item.actualSize = inputActualSize.value.trim();
    DB.saveSession(state.currentSession);
  };
}

// Touch Stepper & Quantity Actions
document.getElementById('btn-qty-add').addEventListener('click', () => {
  if (state.activeScanItem) {
    executeScanForItem(state.activeScanItem);
  }
});

document.getElementById('btn-stepper-plus').addEventListener('click', () => {
  if (state.activeScanItem) {
    state.activeScanItem.actualPhysicalQty += 1;
    displayProductCard(state.activeScanItem, false);
    updateScanViewSummary();
    DB.saveSession(state.currentSession);
  }
});

document.getElementById('btn-stepper-minus').addEventListener('click', () => {
  if (state.activeScanItem && state.activeScanItem.actualPhysicalQty > 0) {
    state.activeScanItem.actualPhysicalQty -= 1;
    displayProductCard(state.activeScanItem, false);
    updateScanViewSummary();
    DB.saveSession(state.currentSession);
  }
});

document.getElementById('btn-qty-undo').addEventListener('click', () => {
  if (!state.currentSession || !state.currentSession.scanHistory.length) {
    showToast('No scan history to undo', 'info');
    return;
  }
  const lastScan = state.currentSession.scanHistory.pop();
  if (lastScan && lastScan.type === 'excel') {
    const item = state.currentSession.items.find(i => i.rowIndex === lastScan.rowIndex);
    if (item && item.scannedQty > 0) {
      item.scannedQty -= 1;
      if (item.actualPhysicalQty > item.scannedQty) {
        item.actualPhysicalQty = item.scannedQty;
      }
      displayProductCard(item, false);
      updateScanViewSummary();
      DB.saveSession(state.currentSession);
      showToast(`Scan undone for EAN ${item.ean}`, 'info');
    }
  }
});

document.getElementById('input-physical-qty').addEventListener('change', (e) => {
  if (state.activeScanItem) {
    const val = parseInt(e.target.value, 10);
    if (!isNaN(val) && val >= 0) {
      state.activeScanItem.actualPhysicalQty = val;
      displayProductCard(state.activeScanItem, false);
      updateScanViewSummary();
      DB.saveSession(state.currentSession);
    }
  }
});

// Single-Scan Verification Confirmation Action
document.getElementById('btn-confirm-next-scan')?.addEventListener('click', () => {
  state.isScanLocked = false; // Unlock single-scan mode
  if (scanInput) scanInput.value = '';
  if (clearInputBtn) clearInputBtn.classList.add('hidden');

  if (state.currentSession) {
    DB.saveSession(state.currentSession);
  }

  showToast('✅ Item Verified & Confirmed! Ready for next scan.', 'success');
  playBeep('success');

  setTimeout(() => {
    const input = document.getElementById('input-barcode-scan');
    if (input) input.focus();
  }, 100);
});

function updateOperatorMonitor() {
  const container = document.getElementById('operator-stats-grid');
  const operatorSelect = document.getElementById('select-operator-filter');
  if (!container || !state.currentSession) return;

  const items = state.currentSession.items || [];
  const extras = state.currentSession.extraStock || [];
  const scanHistory = state.currentSession.scanHistory || [];

  const operatorMap = {};

  scanHistory.forEach(scan => {
    const name = scan.scannedBy || 'Operator';
    if (!operatorMap[name]) {
      operatorMap[name] = { scans: 0, lastActive: scan.timestamp };
    }
    operatorMap[name].scans += 1;
    if (new Date(scan.timestamp) > new Date(operatorMap[name].lastActive)) {
      operatorMap[name].lastActive = scan.timestamp;
    }
  });

  if (state.currentUser && !operatorMap[state.currentUser.name]) {
    operatorMap[state.currentUser.name] = { scans: 0, lastActive: new Date().toISOString() };
  }

  const operatorNames = Object.keys(operatorMap);

  if (operatorSelect) {
    const currentSel = operatorSelect.value;
    operatorSelect.innerHTML = `<option value="all">All Operators (${operatorNames.length})</option>` + 
      operatorNames.map(name => `<option value="${name}">${name} (${operatorMap[name].scans} scans)</option>`).join('');
    if (currentSel) operatorSelect.value = currentSel;
  }

  if (operatorNames.length === 0) {
    container.innerHTML = `<div class="empty-state p-3"><p>No scans recorded yet in the active session.</p></div>`;
    return;
  }

  let totalScans = 0;
  operatorNames.forEach(n => totalScans += operatorMap[n].scans);

  container.innerHTML = operatorNames.map(name => {
    const data = operatorMap[name];
    const pct = totalScans > 0 ? Math.round((data.scans / totalScans) * 100) : 0;
    const timeAgo = data.lastActive ? new Date(data.lastActive).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Now';

    return `
      <div class="operator-stat-card">
        <div class="operator-card-header">
          <span class="operator-name">📱 ${name}</span>
          <span class="badge badge-info">${pct}%</span>
        </div>
        <div class="operator-scans-count">${data.scans} <span style="font-size:0.85rem; font-weight:normal; color:var(--text-muted);">scans</span></div>
        <div class="operator-progress-bar">
          <div class="operator-progress-fill" style="width: ${pct}%"></div>
        </div>
        <div style="font-size:0.75rem; color:var(--text-muted); margin-top:0.2rem;">
          Last scan: ${timeAgo}
        </div>
      </div>
    `;
  }).join('');
}

function updateScanViewSummary() {
  if (!state.currentSession || !state.currentSession.items) return;

  const items = state.currentSession.items;
  const extras = state.currentSession.extraStock || [];

  let totalExpected = 0;
  let totalScanned = 0;
  let totalPending = 0;
  let mrpDiff = 0;
  let sizeDiff = 0;

  items.forEach(item => {
    totalExpected += (item.expectedQty || 0);
    totalScanned += item.scannedQty;
    totalPending += Math.max(0, item.expectedQty - item.scannedQty);

    if (item.mrpStatus === 'Mismatch') mrpDiff++;
    if (item.sizeStatus === 'Mismatch') sizeDiff++;
  });

  document.getElementById('stat-total-expected').textContent = totalExpected;
  document.getElementById('stat-total-scanned').textContent = totalScanned;
  document.getElementById('stat-total-pending').textContent = totalPending;
  document.getElementById('stat-mrp-diff').textContent = mrpDiff;
  document.getElementById('stat-size-diff').textContent = sizeDiff;
  document.getElementById('stat-extra-items').textContent = extras.length;

  updateOperatorMonitor();
}

// ==========================================
// 9. DUPLICATE EAN & EXTRA STOCK MODALS
// ==========================================
function openDuplicateEanModal(ean, items) {
  const modal = document.getElementById('modal-duplicate-ean');
  const container = document.getElementById('duplicate-items-list');

  container.innerHTML = items.map(item => `
    <button type="button" class="duplicate-item-btn" data-row="${item.rowIndex}">
      <div><strong>Row #${item.rowIndex}</strong> &bull; Size: <strong>${item.expectedSize || 'N/A'}</strong> &bull; MRP: <strong>₹${item.expectedMrp}</strong></div>
      <div style="font-size:0.8rem; color: var(--text-muted); margin-top:0.2rem;">
        Pattern: ${item.pattern || '-'} | Design: ${item.design || '-'} | Exp: ${item.expectedQty} | Scanned: ${item.scannedQty}
      </div>
    </button>
  `).join('');

  modal.classList.remove('hidden');

  container.querySelectorAll('.duplicate-item-btn').forEach(btn => {
    btn.onclick = () => {
      const rowIdx = parseInt(btn.getAttribute('data-row'), 10);
      const selectedItem = items.find(i => i.rowIndex === rowIdx);
      modal.classList.add('hidden');
      if (selectedItem) executeScanForItem(selectedItem);
    };
  });
}

document.getElementById('btn-close-duplicate-modal').addEventListener('click', () => {
  document.getElementById('modal-duplicate-ean').classList.add('hidden');
});

function openExtraStockModal(defaultEan = '') {
  const modal = document.getElementById('modal-extra-stock');
  document.getElementById('form-extra-stock').reset();
  document.getElementById('extra-ean').value = defaultEan;
  modal.classList.remove('hidden');
}

document.getElementById('btn-manual-add-extra').addEventListener('click', () => openExtraStockModal(''));
document.getElementById('btn-cancel-extra-modal').addEventListener('click', () => {
  document.getElementById('modal-extra-stock').classList.add('hidden');
});

document.getElementById('form-extra-stock').addEventListener('submit', (e) => {
  e.preventDefault();
  const ean = document.getElementById('extra-ean').value.trim();
  const qty = parseInt(document.getElementById('extra-qty').value, 10) || 1;
  const mrp = parseFloat(document.getElementById('extra-mrp').value) || 0;
  const size = document.getElementById('extra-size').value.trim();
  const brand = document.getElementById('extra-brand').value.trim();
  const design = document.getElementById('extra-design').value.trim();
  const nature = document.getElementById('extra-nature').value.trim();
  const remarks = document.getElementById('extra-remarks').value.trim();

  const extraItem = {
    id: `extra_${Date.now()}`,
    ean,
    expectedQty: 0,
    scannedQty: qty,
    actualPhysicalQty: qty,
    expectedMrp: mrp,
    actualMrp: mrp,
    mrpStatus: 'Unlisted Extra Item',
    expectedSize: size,
    actualSize: size,
    sizeStatus: 'Unlisted Extra Item',
    brand,
    design,
    nature,
    scannedBy: state.currentUser ? state.currentUser.name : 'Operator',
    remarks
  };

  state.currentSession.extraStock.push(extraItem);
  document.getElementById('modal-extra-stock').classList.add('hidden');
  displayProductCard(extraItem, true);
  updateScanViewSummary();
  DB.saveSession(state.currentSession);
  showToast('Unlisted Extra Item added', 'success');
});

// ==========================================
// 10. CAMERA BARCODE SCANNER MODULE (BACK CAMERA OPTIMIZED)
// ==========================================
document.getElementById('btn-open-camera').addEventListener('click', async () => {
  const modal = document.getElementById('modal-camera-scanner');
  modal.classList.remove('hidden');
  startCameraScanner();
});

document.getElementById('btn-close-camera').addEventListener('click', () => {
  stopCameraScanner();
  document.getElementById('modal-camera-scanner').classList.add('hidden');
});

document.getElementById('btn-switch-camera').addEventListener('click', () => {
  if (state.videoDevices.length <= 1) {
    showToast('Only 1 camera detected on device', 'info');
    return;
  }
  state.currentCameraIndex = (state.currentCameraIndex + 1) % state.videoDevices.length;
  const newDeviceId = state.videoDevices[state.currentCameraIndex].deviceId;
  document.getElementById('select-camera-device').value = newDeviceId;
  restartCameraWithDeviceId(newDeviceId);
});

document.getElementById('btn-toggle-torch').addEventListener('click', async () => {
  if (!state.activeStream) return;
  const track = state.activeStream.getVideoTracks()[0];
  if (!track) return;

  try {
    const capabilities = track.getCapabilities ? track.getCapabilities() : {};
    if (!capabilities.torch) {
      showToast('Flashlight torch not supported on this camera', 'info');
      return;
    }

    state.isTorchOn = !state.isTorchOn;
    await track.applyConstraints({ advanced: [{ torch: state.isTorchOn }] });
    const btnTorch = document.getElementById('btn-toggle-torch');
    btnTorch.className = `btn btn-sm ${state.isTorchOn ? 'btn-success' : 'btn-outline'}`;
    showToast(`Torch ${state.isTorchOn ? 'ON' : 'OFF'}`, 'success');
  } catch (err) {
    showToast('Torch feature not supported', 'warning');
  }
});

document.getElementById('select-camera-device').addEventListener('change', (e) => {
  const deviceId = e.target.value;
  if (deviceId) {
    const foundIdx = state.videoDevices.findIndex(d => d.deviceId === deviceId);
    if (foundIdx !== -1) state.currentCameraIndex = foundIdx;
    restartCameraWithDeviceId(deviceId);
  }
});

async function startCameraScanner() {
  if (state.isScanningCamera) return;

  try {
    if (!window.ZXing) {
      showToast('ZXing camera library loading...', 'info');
      return;
    }

    const codeReader = new ZXing.BrowserMultiFormatReader();
    state.zxingReader = codeReader;

    const devices = await codeReader.listVideoInputDevices();
    state.videoDevices = devices || [];

    if (state.videoDevices.length === 0) {
      showToast('No video camera devices found', 'error');
      return;
    }

    const select = document.getElementById('select-camera-device');
    select.innerHTML = state.videoDevices.map((device, idx) => 
      `<option value="${device.deviceId}">${device.label || `Camera ${idx + 1}`}</option>`
    ).join('');

    let backCameraIdx = -1;
    const backKeywords = ['back', 'rear', 'environment', 'main', 'facing back', '0', 'wide'];
    
    state.videoDevices.forEach((device, idx) => {
      const label = (device.label || '').toLowerCase();
      if (backKeywords.some(kw => label.includes(kw))) {
        if (backCameraIdx === -1) backCameraIdx = idx;
      }
    });

    if (backCameraIdx === -1) {
      backCameraIdx = state.videoDevices.length > 1 ? state.videoDevices.length - 1 : 0;
    }

    state.currentCameraIndex = backCameraIdx;
    const selectedDeviceId = state.videoDevices[backCameraIdx].deviceId;
    select.value = selectedDeviceId;

    startDecodingWithDeviceId(selectedDeviceId);

  } catch (err) {
    console.error('Camera scanner start error:', err);
    showToast('Could not open camera', 'error');
  }
}

function startDecodingWithDeviceId(deviceId) {
  if (!state.zxingReader) return;

  const cameraNameBadge = document.getElementById('active-camera-name');
  const currentDevice = state.videoDevices[state.currentCameraIndex];
  cameraNameBadge.textContent = currentDevice ? (currentDevice.label || `Camera ${state.currentCameraIndex + 1}`) : 'Active Camera';

  let lastScanTime = 0;
  let lastScanCode = '';

  state.zxingReader.decodeFromVideoDevice(deviceId, 'camera-video', (result, err) => {
    if (result && !state.isScanLocked) {
      const code = result.getText();
      stopCameraScanner();
      document.getElementById('modal-camera-scanner')?.classList.add('hidden');
      handleBarcodeScan(code);
    }
  }).then(controls => {
    const videoElem = document.getElementById('camera-video');
    if (videoElem && videoElem.srcObject) {
      state.activeStream = videoElem.srcObject;
    }
  }).catch(err => { console.warn(err); });

  state.isScanningCamera = true;
}

function restartCameraWithDeviceId(deviceId) {
  if (state.zxingReader) state.zxingReader.reset();
  state.isTorchOn = false;
  document.getElementById('btn-toggle-torch').className = 'btn btn-sm btn-outline';
  startDecodingWithDeviceId(deviceId);
}

function stopCameraScanner() {
  if (state.zxingReader) {
    state.zxingReader.reset();
    state.zxingReader = null;
  }
  state.activeStream = null;
  state.isTorchOn = false;
  state.isScanningCamera = false;
}

// ==========================================
// 11. WEBRTC MULTI-DEVICE LIVE SYNC MODULE (PeerJS)
// ==========================================
document.getElementById('btn-open-sync-modal').addEventListener('click', () => {
  document.getElementById('modal-peer-sync').classList.remove('hidden');
});

document.getElementById('btn-close-peer-modal').addEventListener('click', () => {
  document.getElementById('modal-peer-sync').classList.add('hidden');
});

// Host Session Mode (Manager / Admin)
document.getElementById('btn-start-peer-host').addEventListener('click', () => {
  if (!window.Peer) {
    showToast('PeerJS library loading...', 'info');
    return;
  }

  const pinCode = Math.floor(1000 + Math.random() * 9000);
  const peerId = `GV-SYNC-${pinCode}`;

  try {
    state.peer = new Peer(peerId);
    state.isPeerHost = true;

    state.peer.on('open', (id) => {
      document.getElementById('display-host-code').textContent = `GV-${pinCode}`;
      document.getElementById('connected-peers-box').classList.remove('hidden');
      showToast(`Hosting Sync Session: GV-${pinCode}`, 'success');
    });

    state.peer.on('connection', (conn) => {
      state.peerConnections.push(conn);
      showToast(`Scanner Connected: ${conn.peer}`, 'info');

      conn.on('data', (data) => {
        if (data && data.type === 'SCAN_PAYLOAD') {
          handleRemoteScanPayload(data);
        }
      });
    });

  } catch (err) {
    console.error('Peer host error:', err);
    showToast('Failed to start multi-device host', 'error');
  }
});

// Client Join Mode (Scanner Phones)
document.getElementById('btn-connect-peer-join').addEventListener('click', () => {
  const codeInput = document.getElementById('input-join-code').value.trim().toUpperCase();
  if (!codeInput) {
    showToast('Enter 6-digit Sync Code from Manager device', 'warning');
    return;
  }

  const targetPeerId = codeInput.startsWith('GV-SYNC-') ? codeInput : `GV-SYNC-${codeInput.replace('GV-', '')}`;

  try {
    state.peer = new Peer();
    state.peer.on('open', () => {
      const conn = state.peer.connect(targetPeerId);
      conn.on('open', () => {
        state.peerConnections.push(conn);
        showToast(`Connected to Manager Session: ${targetPeerId}`, 'success');
        document.getElementById('modal-peer-sync').classList.add('hidden');
      });
      conn.on('data', (data) => {
        if (data.type === 'SESSION_SYNC') {
          state.currentSession = data.session;
          updateScanViewSummary();
          showToast('Live session synced from Manager', 'info');
        }
      });
    });
  } catch (err) {
    showToast('Could not connect to host device', 'error');
  }
});

function broadcastScanToPeers(scanRecord) {
  if (state.peerConnections.length === 0) return;
  state.peerConnections.forEach(conn => {
    if (conn.open) {
      conn.send({ type: 'SCAN_PAYLOAD', scanRecord, item: state.activeScanItem, scannedBy: state.currentUser?.name });
    }
  });
}

function handleRemoteScanPayload(payload) {
  if (!state.currentSession || !payload.scanRecord) return;
  const ean = payload.scanRecord.ean;
  const matchingItem = state.currentSession.items.find(i => i.ean.toLowerCase() === ean.toLowerCase());
  if (matchingItem) {
    matchingItem.scannedQty += 1;
    matchingItem.scannedBy = payload.scannedBy || 'Remote Scanner';
    displayProductCard(matchingItem, false);
    updateScanViewSummary();
    DB.saveSession(state.currentSession);
    showToast(`Remote Scan Received from ${payload.scannedBy}: EAN ${ean}`, 'success');
  }
}

// ==========================================
// 12. INVENTORY OVERVIEW & EXCEPTION SCREEN
// ==========================================
function renderInventoryOverview() {
  if (!state.currentSession) return;

  const items = state.currentSession.items || [];
  const extras = state.currentSession.extraStock || [];
  const filterVal = document.getElementById('select-overview-filter').value;
  const operatorVal = document.getElementById('select-operator-filter')?.value || 'all';
  const searchVal = document.getElementById('input-overview-search').value.toLowerCase().trim();

  let totalExpected = 0, totalScanned = 0, totalPending = 0, mrpDiff = 0, sizeDiff = 0;
  items.forEach(item => {
    totalExpected += (item.expectedQty || 0);
    totalScanned += item.scannedQty;
    totalPending += Math.max(0, item.expectedQty - item.scannedQty);
    if (item.mrpStatus === 'Mismatch') mrpDiff++;
    if (item.sizeStatus === 'Mismatch') sizeDiff++;
  });

  document.getElementById('ov-stat-total-items').textContent = items.length;
  document.getElementById('ov-stat-expected-units').textContent = totalExpected;
  document.getElementById('ov-stat-scanned-units').textContent = totalScanned;
  document.getElementById('ov-stat-pending-units').textContent = totalPending;
  document.getElementById('ov-stat-mrp-diff').textContent = mrpDiff;
  document.getElementById('ov-stat-size-diff').textContent = sizeDiff;
  document.getElementById('ov-stat-extra-items').textContent = extras.length;

  let combined = [
    ...items.map(i => ({ ...i, isExtra: false })),
    ...extras.map(e => ({ ...e, isExtra: true }))
  ];

  const currentUserName = state.currentUser ? state.currentUser.name : '';

  if (searchVal) {
    combined = combined.filter(i => 
      (i.ean && i.ean.toLowerCase().includes(searchVal)) ||
      (i.brand && i.brand.toLowerCase().includes(searchVal)) ||
      (i.design && i.design.toLowerCase().includes(searchVal)) ||
      (i.nature && i.nature.toLowerCase().includes(searchVal)) ||
      (i.scannedBy && i.scannedBy.toLowerCase().includes(searchVal))
    );
  }

  if (operatorVal !== 'all') {
    combined = combined.filter(i => i.scannedBy === operatorVal);
  }

  if (filterVal === 'my_scans' || state.currentUser?.role === 'USER') {
    combined = combined.filter(i => i.scannedBy === currentUserName || !i.scannedBy);
  } else if (filterVal === 'pending') combined = combined.filter(i => !i.isExtra && i.scannedQty < i.expectedQty);
  else if (filterVal === 'verified') combined = combined.filter(i => i.scannedQty > 0);
  else if (filterVal === 'mrp_diff') combined = combined.filter(i => i.mrpStatus === 'Mismatch');
  else if (filterVal === 'size_diff') combined = combined.filter(i => i.sizeStatus === 'Mismatch');
  else if (filterVal === 'excess') combined = combined.filter(i => i.actualPhysicalQty > i.expectedQty);
  else if (filterVal === 'extra') combined = combined.filter(i => i.isExtra);

  const tbody = document.getElementById('tbody-inventory-overview');
  tbody.innerHTML = combined.map(item => {
    const qtyDiff = item.actualPhysicalQty - (item.expectedQty || 0);
    let statusBadge = '<span class="badge badge-warning">Pending</span>';

    if (item.isExtra) {
      statusBadge = '<span class="badge badge-danger">Unlisted Extra</span>';
    } else if (item.actualPhysicalQty > item.expectedQty) {
      statusBadge = '<span class="badge badge-danger">Excess Stock</span>';
    } else if (item.mrpStatus === 'Mismatch' || item.sizeStatus === 'Mismatch') {
      statusBadge = '<span class="badge badge-warning">Mismatch Alert</span>';
    } else if (item.actualPhysicalQty === item.expectedQty && item.expectedQty > 0) {
      statusBadge = '<span class="badge badge-success">Verified OK</span>';
    }

    return `
      <tr>
        <td>${item.isExtra ? 'EXTRA' : `#${item.rowIndex}`}</td>
        <td><strong>${item.ean}</strong></td>
        <td>${item.brand || 'Item'} - ${item.nature || ''} (${item.design || ''})</td>
        <td>${item.actualSize || item.expectedSize || '-'}</td>
        <td>₹${item.actualMrp || item.expectedMrp || 0}</td>
        <td>${item.expectedQty || 0}</td>
        <td><strong>${item.scannedQty}</strong></td>
        <td><strong>${item.actualPhysicalQty}</strong></td>
        <td><small>${item.scannedBy || 'System'}</small></td>
        <td>${statusBadge}</td>
        <td>
          <button class="btn btn-sm btn-outline btn-verify-row" data-row="${item.rowIndex}" data-extra="${item.isExtra ? item.id : ''}">
            Verify
          </button>
        </td>
      </tr>
    `;
  }).join('');

  tbody.querySelectorAll('.btn-verify-row').forEach(btn => {
    btn.onclick = () => {
      const extraId = btn.getAttribute('data-extra');
      const rowNum = parseInt(btn.getAttribute('data-row'), 10);
      if (extraId) {
        const extraItem = state.currentSession.extraStock.find(e => e.id === extraId);
        if (extraItem) displayProductCard(extraItem, true);
      } else {
        const item = state.currentSession.items.find(i => i.rowIndex === rowNum);
        if (item) displayProductCard(item, false);
      }
      switchView('scan');
    };
  });
}

document.getElementById('input-overview-search').addEventListener('input', renderInventoryOverview);
document.getElementById('select-overview-filter').addEventListener('change', renderInventoryOverview);
document.getElementById('select-operator-filter')?.addEventListener('change', renderInventoryOverview);

// ==========================================
// 13. REVIEW & EXPORT ENGINE (ENCRYPTED JSON & EXCEL)
// ==========================================
function renderExportReview() {
  if (!state.currentSession) return;

  const s = state.currentSession;
  const items = s.items || [];
  const extras = s.extraStock || [];

  let totalExpected = 0, totalPhysical = 0, totalPending = 0, mrpDiff = 0, sizeDiff = 0;
  items.forEach(item => {
    totalExpected += (item.expectedQty || 0);
    totalPhysical += item.actualPhysicalQty;
    totalPending += Math.max(0, item.expectedQty - item.scannedQty);
    if (item.mrpStatus === 'Mismatch') mrpDiff++;
    if (item.sizeStatus === 'Mismatch') sizeDiff++;
  });

  document.getElementById('exp-val-supplier').textContent = s.supplierName;
  document.getElementById('exp-val-invoice').textContent = s.invoiceNo;
  document.getElementById('exp-val-date').textContent = s.verificationDate;
  document.getElementById('exp-val-lines').textContent = items.length;
  document.getElementById('exp-val-expected').textContent = totalExpected;
  document.getElementById('exp-val-physical').textContent = totalPhysical;
  document.getElementById('exp-val-pending').textContent = totalPending;
  document.getElementById('exp-val-mrp-mismatch').textContent = mrpDiff;
  document.getElementById('exp-val-size-mismatch').textContent = sizeDiff;
  document.getElementById('exp-val-extra').textContent = extras.length;
}

// Download Verified Excel (.xlsx) - Manager & Admin Only
document.getElementById('btn-download-excel').addEventListener('click', () => {
  if (state.currentUser?.role === 'USER') {
    showToast('Users cannot download master Excel files. Manager/Admin role required.', 'error');
    return;
  }

  if (!state.currentSession || !state.currentSession.excelRawData) {
    showToast('No active session data to export', 'error');
    return;
  }

  try {
    const rawData = state.currentSession.excelRawData;
    const originalHeaders = rawData[0].map(h => String(h).trim());

    const verificationHeaders = [
      'Scanned Qty',
      'Actual Physical Qty',
      'Qty Difference',
      'Actual MRP',
      'MRP Verification Status',
      'Actual Size',
      'Size Verification Status',
      'Actual Brand / Item',
      'Verification Status',
      'Scanned By User',
      'Remarks'
    ];

    const newHeaderRow = [...originalHeaders, ...verificationHeaders];
    const newRows = [newHeaderRow];

    const items = state.currentSession.items || [];
    const mapping = state.currentSession.columnMapping;

    state.excelRows.forEach((rawRow, idx) => {
      const item = items.find(i => i.rowIndex === (idx + 1)) || {};

      const qtyDiff = (item.actualPhysicalQty || 0) - (item.expectedQty || 0);
      let statusStr = 'Pending';
      if (item.actualPhysicalQty > item.expectedQty) {
        statusStr = 'Excess Stock';
      } else if (item.mrpStatus === 'Mismatch' || item.sizeStatus === 'Mismatch') {
        statusStr = 'Verified - Mismatch Alert';
      } else if (item.actualPhysicalQty === item.expectedQty && item.expectedQty > 0) {
        statusStr = 'Verified - OK';
      }

      const verCols = [
        item.scannedQty || 0,
        item.actualPhysicalQty || 0,
        qtyDiff,
        item.actualMrp !== undefined ? item.actualMrp : (item.expectedMrp || ''),
        item.mrpStatus || 'Not Verified',
        item.actualSize || (item.expectedSize || ''),
        item.sizeStatus || 'Not Verified',
        item.brand || '',
        statusStr,
        item.scannedBy || 'System',
        item.remarks || ''
      ];

      newRows.push([...rawRow, ...verCols]);
    });

    const extras = state.currentSession.extraStock || [];
    extras.forEach(extra => {
      const extraRow = new Array(originalHeaders.length).fill('');
      
      if (mapping.ean !== undefined) extraRow[mapping.ean] = extra.ean;
      if (mapping.qty !== undefined) extraRow[mapping.qty] = 0;
      if (mapping.mrp !== undefined) extraRow[mapping.mrp] = extra.actualMrp;
      if (mapping.size !== undefined) extraRow[mapping.size] = extra.actualSize;
      if (mapping.brand !== undefined) extraRow[mapping.brand] = extra.brand;
      if (mapping.design !== undefined) extraRow[mapping.design] = extra.design;
      if (mapping.nature !== undefined) extraRow[mapping.nature] = extra.nature;

      const verCols = [
        extra.scannedQty || extra.actualPhysicalQty,
        extra.actualPhysicalQty,
        extra.actualPhysicalQty,
        extra.actualMrp,
        'Unlisted Extra Item',
        extra.actualSize,
        'Unlisted Extra Item',
        extra.brand || '',
        'Unlisted Extra Item',
        extra.scannedBy || 'System',
        extra.remarks || ''
      ];

      newRows.push([...extraRow, ...verCols]);
    });

    const ws = XLSX.utils.aoa_to_sheet(newRows);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Verified Inventory');

    const cleanSupplier = state.currentSession.supplierName.replace(/[^a-zA-Z0-9]/g, '_');
    const cleanInvoice = state.currentSession.invoiceNo.replace(/[^a-zA-Z0-9]/g, '_');
    const fileName = `Verified_Inventory_${cleanSupplier}_${cleanInvoice}.xlsx`;

    XLSX.writeFile(wb, fileName);
    showToast('Verified Excel report downloaded!', 'success');

  } catch (err) {
    console.error('Excel Export Error:', err);
    showToast('Failed to generate Excel export file', 'error');
  }
});

// Download 256-Bit Encrypted JSON Backup
document.getElementById('btn-download-json-backup').addEventListener('click', async () => {
  if (!state.currentSession) return;
  const pass = state.currentUser ? state.currentUser.passcode : 'DefaultMasterKey2026';
  const encryptedPayload = await encryptPayload(state.currentSession, pass);

  const backupObj = {
    app: 'GarmentVerifyEncryptedBackup',
    version: '2.0',
    supplierName: state.currentSession.supplierName,
    invoiceNo: state.currentSession.invoiceNo,
    encryptedData: encryptedPayload
  };

  const jsonStr = JSON.stringify(backupObj, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `EncryptedBackup_${state.currentSession.supplierName}_${state.currentSession.invoiceNo}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('256-bit encrypted JSON backup downloaded', 'success');
});

document.getElementById('input-json-backup').addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = async (evt) => {
    try {
      const backupObj = JSON.parse(evt.target.result);
      const pass = state.currentUser ? state.currentUser.passcode : 'DefaultMasterKey2026';
      
      let sessionData = null;
      if (backupObj.encryptedData) {
        sessionData = await decryptPayload(backupObj.encryptedData, pass);
      } else {
        sessionData = backupObj;
      }

      state.currentSession = sessionData;
      await DB.saveSession(sessionData);
      updateNavPill();
      updateScanViewSummary();
      switchView('scan');
      showToast('Encrypted session backup restored successfully!', 'success');
    } catch (err) {
      showToast('Failed to decrypt backup JSON. Verify your role passcode.', 'error');
    }
  };
  reader.readAsText(file);
});

// Admin Session & Raw File Deletion
document.getElementById('btn-admin-delete-session')?.addEventListener('click', async () => {
  if (state.currentUser?.role !== 'ADMIN') {
    showToast('Admin permission required to delete sessions permanently.', 'error');
    return;
  }

  if (!state.currentSession) return;

  if (confirm(`ADMIN CONFIRMATION:\n\nAre you sure you want to PERMANENTLY DELETE session '${state.currentSession.supplierName}' (Invoice: ${state.currentSession.invoiceNo}) and its uploaded raw Excel data?`)) {
    await DB.deleteSession(state.currentSession.id);
    state.currentSession = null;
    updateNavPill();
    switchView('dashboard');
    renderSavedSessionsList();
    showToast('Session & Raw Excel file deleted permanently by Admin.', 'info');
  }
});

// Saved Encrypted Sessions List Manager
async function renderSavedSessionsList(skipCloudSync = false) {
  if (!skipCloudSync) {
    await CloudSync.syncAllFromCloud(true);
  }
  const sessions = await DB.getAllSessions();
  const container = document.getElementById('saved-sessions-list');

  if (sessions.length === 0) {
    container.innerHTML = `<div class="empty-state"><p>No saved encrypted sessions found.</p></div>`;
    return;
  }

  container.innerHTML = sessions.map(s => `
    <div class="session-card">
      <div>
        <div class="session-title-text">${s.supplierName}</div>
        <div class="session-meta-text">Inv: ${s.invoiceNo} &bull; 🔒 Encrypted ☁️</div>
      </div>
      <div class="session-actions">
        <button class="btn btn-sm btn-primary btn-resume-session" data-id="${s.id}">Resume</button>
        ${state.currentUser?.role === 'ADMIN' ? `<button class="btn btn-sm btn-outline btn-delete-session" data-id="${s.id}">Delete</button>` : ''}
      </div>
    </div>
  `).join('');

  container.querySelectorAll('.btn-resume-session').forEach(btn => {
    btn.onclick = async () => {
      const id = btn.getAttribute('data-id');
      try {
        const session = await DB.getSession(id);
        if (session) {
          state.currentSession = session;
          state.excelRawData = session.excelRawData;
          state.excelHeaders = session.excelHeaders || [];
          state.excelRows = session.excelRawData ? session.excelRawData.slice(1) : [];
          updateNavPill();
          updateScanViewSummary();
          switchView('scan');
          showToast('Session decrypted & resumed', 'success');
        }
      } catch (err) {
        showToast('Decryption failed. Password mismatch.', 'error');
      }
    };
  });

  container.querySelectorAll('.btn-delete-session').forEach(btn => {
    btn.onclick = async () => {
      if (state.currentUser?.role !== 'ADMIN') {
        showToast('Admin role required to delete files.', 'error');
        return;
      }

      const id = btn.getAttribute('data-id');
      if (confirm('ADMIN: Delete this session permanently?')) {
        await DB.deleteSession(id);
        renderSavedSessionsList(true);
        showToast('Session deleted', 'info');
      }
    };
  });
}

document.getElementById('btn-refresh-sessions').addEventListener('click', () => {
  showToast('Refreshing sessions from Cloud & Local...', 'info');
  renderSavedSessionsList(false);
});

// ==========================================
// 14. CLOUD SYNC MODAL BINDINGS & CONTROLS
// ==========================================
function openCloudSyncModal() {
  const modal = document.getElementById('modal-cloud-sync');
  if (!modal) return;

  const repoInput = document.getElementById('input-github-repo');
  const branchInput = document.getElementById('input-github-branch');
  const tokenInput = document.getElementById('input-github-token');
  const cloudInput = document.getElementById('input-cloud-endpoint');
  const badge = document.getElementById('cloud-status-badge');

  const config = GitHubSync.getConfig();
  const cloudUrl = localStorage.getItem('garment_verify_cloud_url') || '';

  if (repoInput) repoInput.value = config.repo;
  if (branchInput) branchInput.value = config.branch;
  if (tokenInput) tokenInput.value = config.token;
  if (cloudInput) cloudInput.value = cloudUrl;

  if (badge) {
    if (config.repo || cloudUrl) {
      badge.textContent = `🟢 Auto-Sync Active (${config.repo ? 'GitHub' : 'Cloud'})`;
      badge.className = 'badge badge-success';
    } else {
      badge.textContent = '🟡 Enter GitHub Repo (Username/RepoName)';
      badge.className = 'badge badge-warning';
    }
  }

  modal.classList.remove('hidden');
}

function closeCloudSyncModal() {
  document.getElementById('modal-cloud-sync')?.classList.add('hidden');
}

document.getElementById('btn-cloud-sync-header')?.addEventListener('click', openCloudSyncModal);
document.getElementById('btn-sync-cloud-now')?.addEventListener('click', openCloudSyncModal);
document.getElementById('btn-close-cloud-modal')?.addEventListener('click', closeCloudSyncModal);

document.getElementById('btn-github-pull-now')?.addEventListener('click', async () => {
  const repo = document.getElementById('input-github-repo').value.trim();
  const branch = document.getElementById('input-github-branch').value.trim() || 'main';
  const token = document.getElementById('input-github-token').value.trim();
  GitHubSync.setConfig(repo, branch, token);

  showToast('Fetching latest DB from GitHub Repository...', 'info');
  const success = await GitHubSync.pullFromGitHub(false);
  if (success) {
    await renderSavedSessionsList(true);
  }
});

document.getElementById('btn-export-db-json')?.addEventListener('click', async () => {
  await GitHubSync.exportDbJsonFile();
});

document.getElementById('btn-save-cloud-endpoint')?.addEventListener('click', async () => {
  const repo = document.getElementById('input-github-repo').value.trim();
  const branch = document.getElementById('input-github-branch').value.trim() || 'main';
  const token = document.getElementById('input-github-token').value.trim();
  const cloudUrl = document.getElementById('input-cloud-endpoint').value.trim();

  GitHubSync.setConfig(repo, branch, token);
  if (cloudUrl) localStorage.setItem('garment_verify_cloud_url', cloudUrl);
  else localStorage.removeItem('garment_verify_cloud_url');

  showToast('Sync settings saved successfully!', 'success');
  await GitHubSync.pullFromGitHub(true);
  await CloudSync.syncAllFromCloud(true);
  await renderSavedSessionsList(true);
  closeCloudSyncModal();
});

document.getElementById('btn-reset-cloud-endpoint')?.addEventListener('click', async () => {
  GitHubSync.setConfig('', 'main', '');
  localStorage.removeItem('garment_verify_cloud_url');
  showToast('Cleared Sync Settings', 'info');
  openCloudSyncModal();
});

// Navigation Clicks
document.querySelectorAll('.nav-btn, .mobile-nav-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const viewId = btn.getAttribute('data-view');
    switchView(viewId);
  });
});

// Init Application & Check Auth
window.addEventListener('DOMContentLoaded', async () => {
  const dateInput = document.getElementById('input-date');
  if (dateInput) dateInput.value = new Date().toISOString().split('T')[0];
  renderUserManagementList();
  checkAuthOnLoad();
  await GitHubSync.pullFromGitHub(true);
  await CloudSync.syncAllFromCloud(true);
  renderSavedSessionsList(true);
});
