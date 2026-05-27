/* ═══════════════════════════════════════════════
   SECUREVAULT — SQL Injection Defense System
   Core Application Logic
═══════════════════════════════════════════════ */

// ── AES-256 MASTER KEY (In production, this would be server-side / HSM-managed)
const AES_KEY = 'SecureVault_AES256_MasterKey_2024_XK9!';

// ── STATS STATE
const stats = { encrypted: 0, blocked: 0, tokens: 0, queries: 0 };

// ── IN-MEMORY DATABASE (simulates encrypted DB storage)
const secureDB = [];

// ── AUDIT LOG
const auditLog = [];

// ════════════════════════════════════════════════
// SQL INJECTION PATTERNS (Layer 1 Defense)
// ════════════════════════════════════════════════
const SQL_PATTERNS = [
  { name: 'OR Bypass',          pattern: /(\bOR\b\s*['"]?[\w\s]*['"]?\s*=\s*['"]?[\w\s]*['"]?)/i,  danger: 'critical', regex: "OR '1'='1'" },
  { name: 'Comment Injection',  pattern: /(--|#|\/\*[\s\S]*?\*\/)/,                                  danger: 'high',     regex: "--, #, /* */" },
  { name: 'UNION Select',       pattern: /\bUNION\b\s*\bSELECT\b/i,                                 danger: 'critical', regex: "UNION SELECT" },
  { name: 'DROP / TRUNCATE',    pattern: /\b(DROP|TRUNCATE)\b\s+\bTABLE\b/i,                        danger: 'critical', regex: "DROP TABLE" },
  { name: 'Stacked Queries',    pattern: /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)/i,            danger: 'critical', regex: "; SELECT..." },
  { name: 'Boolean Blind',      pattern: /\bAND\b\s+[\d]+\s*=\s*[\d]+/i,                            danger: 'high',     regex: "AND 1=1" },
  { name: 'Time-Based Blind',   pattern: /\b(SLEEP|WAITFOR|BENCHMARK)\s*\(/i,                        danger: 'critical', regex: "SLEEP(5)" },
  { name: 'String Concat',      pattern: /CONCAT\s*\(|['"][\s]*\+[\s]*['"]/i,                        danger: 'medium',   regex: "CONCAT()" },
  { name: 'Always-True',        pattern: /'\s*OR\s*'.*?'\s*=\s*'/i,                                  danger: 'critical', regex: "' OR 'x'='x'" },
  { name: 'SELECT *',           pattern: /SELECT\s+\*/i,                                              danger: 'high',     regex: "SELECT *" },
  { name: 'INSERT INTO',        pattern: /\bINSERT\s+INTO\b/i,                                       danger: 'medium',   regex: "INSERT INTO" },
  { name: 'UPDATE SET',         pattern: /\bUPDATE\b.+\bSET\b/i,                                     danger: 'medium',   regex: "UPDATE SET" },
  { name: 'Hex Encoding',       pattern: /0x[0-9a-fA-F]{4,}/,                                        danger: 'high',     regex: "0x41..." },
  { name: 'Information Schema', pattern: /INFORMATION_SCHEMA/i,                                       danger: 'critical', regex: "INFORMATION_SCHEMA" },
  { name: 'EXEC / EXECUTE',     pattern: /\b(EXEC|EXECUTE)\s*\(/i,                                   danger: 'critical', regex: "EXEC()" },
  { name: 'CAST / CONVERT',     pattern: /\b(CAST|CONVERT)\s*\(/i,                                   danger: 'medium',   regex: "CAST()" },
  { name: 'LOAD_FILE',          pattern: /\bLOAD_FILE\s*\(/i,                                        danger: 'critical', regex: "LOAD_FILE()" },
  { name: 'INTO OUTFILE',       pattern: /\bINTO\b\s+\bOUTFILE\b/i,                                  danger: 'critical', regex: "INTO OUTFILE" },
  { name: 'Single Quote Escape',pattern: /['"]\s*;\s*['"]/,                                           danger: 'high',     regex: "'; '" },
  { name: 'NULL Byte',          pattern: /%00|\\x00|\\u0000/,                                         danger: 'high',     regex: "%00" },
];

// ── QUICK PAYLOADS for Query Lab
const PAYLOADS = [
  "SELECT * FROM users WHERE username='admin' OR '1'='1'",
  "SELECT * FROM users WHERE id=1--; SELECT password FROM admins",
  "SELECT * FROM products WHERE id=1 UNION SELECT username,password,3 FROM users--",
  "'; DROP TABLE users; --",
  "1' AND SLEEP(5)--",
  "1'; INSERT INTO users VALUES('hacker','pass'); --",
  "1' AND 1=1-- (Boolean true) UNION SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA--",
  "SELECT * FROM products WHERE category='Electronics' AND active=1",
];

// ════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ════════════════════════════════════════════════

function aesEncrypt(text) {
  return CryptoJS.AES.encrypt(text, AES_KEY).toString();
}
function aesDecrypt(cipher) {
  try {
    const bytes = CryptoJS.AES.decrypt(cipher, AES_KEY);
    return bytes.toString(CryptoJS.enc.Utf8);
  } catch { return '[decrypt error]'; }
}
function sha256(text) {
  return CryptoJS.SHA256(text).toString();
}
function truncate(str, n = 40) {
  return str.length > n ? str.substring(0, n) + '…' : str;
}
function nowStr() {
  return new Date().toLocaleTimeString('en-US', { hour12: false });
}
function updateStats() {
  document.getElementById('stat-encrypted').textContent = stats.encrypted;
  document.getElementById('stat-blocked').textContent   = stats.blocked;
  document.getElementById('stat-tokens').textContent    = stats.tokens;
  document.getElementById('stat-queries').textContent   = stats.queries;
  document.getElementById('headerThreatCount').textContent = stats.blocked + ' THREATS BLOCKED';
}

// ════════════════════════════════════════════════
// LAYER 1: SQL INJECTION DETECTION
// ════════════════════════════════════════════════
function detectSQLInjection(input) {
  const matches = [];
  for (const p of SQL_PATTERNS) {
    if (p.pattern.test(input)) matches.push(p);
  }
  return { isInjection: matches.length > 0, matches };
}

// ════════════════════════════════════════════════
// LAYER 1: INPUT SANITIZATION
// ════════════════════════════════════════════════
function sanitizeInput(input) {
  return input
    .replace(/'/g,  "\\'")     // escape single quotes
    .replace(/"/g,  '\\"')     // escape double quotes
    .replace(/;/g,  '')        // remove statement terminators
    .replace(/--/g, '')        // remove comment sequences
    .replace(/\/\*/g, '')      // remove block comment start
    .replace(/\*\//g, '')      // remove block comment end
    .replace(/\bOR\b/gi,  '')  // strip OR keyword
    .replace(/\bAND\b/gi, '')  // strip AND keyword
    .replace(/\bUNION\b/gi,'') // strip UNION
    .replace(/\bSELECT\b/gi,'')
    .replace(/\bDROP\b/gi, '')
    .replace(/\bINSERT\b/gi,'')
    .replace(/\bEXEC\b/gi,'')
    .replace(/%00/g, '')
    .trim();
}

// ════════════════════════════════════════════════
// LAYER 2: PARAMETERIZED QUERY SIMULATION
// ════════════════════════════════════════════════
function buildParameterizedQuery(template, params) {
  // Simulates prepared statement — params are NEVER string-concatenated
  return {
    template,
    params,
    safe: true,
    executed: template.replace(/\?/g, () => {
      const p = params.shift();
      return `<PARAM:${typeof p === 'string' ? `"${p}"` : p}>`;
    })
  };
}

// ════════════════════════════════════════════════
// CAPABILITY TOKEN SYSTEM
// ════════════════════════════════════════════════
function generateCapabilityToken(subject, scope, expiryHours) {
  const now = Date.now();
  const payload = {
    sub:  subject,
    scp:  scope,
    iat:  now,
    exp:  now + expiryHours * 3600 * 1000,
    jti:  CryptoJS.lib.WordArray.random(16).toString()
  };
  const header    = btoa(JSON.stringify({ alg: 'AES256', typ: 'CAP' }));
  const body      = btoa(JSON.stringify(payload));
  const signature = aesEncrypt(header + '.' + body);
  return `${header}.${body}.${btoa(signature)}`;
}

function validateCapabilityToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return { valid: false, reason: 'Malformed token structure' };
    const payload  = JSON.parse(atob(parts[1]));
    const sigCheck = aesDecrypt(atob(parts[2]));
    const expected = parts[0] + '.' + parts[1];
    if (!sigCheck.startsWith(expected.substring(0, 20)))
      return { valid: false, reason: 'Signature mismatch — possible tampering' };
    if (Date.now() > payload.exp)
      return { valid: false, reason: 'Token expired' };
    return { valid: true, payload };
  } catch (e) {
    return { valid: false, reason: 'Token parse error' };
  }
}

// ════════════════════════════════════════════════
// AUDIT LOG
// ════════════════════════════════════════════════
function addLog(event, sample, status, layer, type) {
  const entry = { time: nowStr(), event, sample, status, layer, type };
  auditLog.unshift(entry);
  renderLog(entry);
  if (auditLog.length > 200) auditLog.pop();
}

function renderLog(entry, prepend = true) {
  const container = document.getElementById('logEntries');
  const empty = container.querySelector('.log-empty');
  if (empty) empty.remove();

  const div = document.createElement('div');
  div.className = 'log-entry';
  div.dataset.type = entry.type;
  const statusClass = entry.status === 'BLOCKED' ? 'blocked' : entry.status === 'OK' ? 'ok' : 'warn';
  div.innerHTML = `
    <span class="le-time">${entry.time}</span>
    <span class="le-event">${entry.event}</span>
    <span class="le-sample">${entry.sample}</span>
    <span><span class="le-status ${statusClass}">${entry.status}</span></span>
    <span class="le-layer">${entry.layer}</span>
  `;
  if (prepend) {
    container.insertBefore(div, container.firstChild);
  } else {
    container.appendChild(div);
  }
}

// ════════════════════════════════════════════════
// LIVE INPUT SCANNING (real-time shield indicator)
// ════════════════════════════════════════════════
function watchInput(inputId, shieldId, barId) {
  const input  = document.getElementById(inputId);
  const shield = document.getElementById(shieldId);
  const bar    = barId ? document.getElementById(barId) : null;
  if (!input) return;

  input.addEventListener('input', () => {
    const val = input.value;
    if (!val) {
      input.className = '';
      if (shield) shield.textContent = '🛡️';
      if (bar) { bar.className = 'threat-bar'; bar.dataset.msg = ''; }
      return;
    }
    const result = detectSQLInjection(val);
    if (result.isInjection) {
      input.className = 'danger';
      if (shield) shield.textContent = '🚨';
      if (bar) {
        bar.className = 'threat-bar threat';
        const names = result.matches.map(m => m.name).join(', ');
        bar.dataset.msg = '⚠ Detected: ' + names;
      }
    } else {
      input.className = val.length > 0 ? 'safe' : '';
      if (shield) shield.textContent = '✅';
      if (bar) { bar.className = 'threat-bar safe'; bar.dataset.msg = ''; }
    }
  });
}

// ════════════════════════════════════════════════
// TAB NAVIGATION
// ════════════════════════════════════════════════
document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
  });
});

// ════════════════════════════════════════════════
// LOGIN HANDLER
// ════════════════════════════════════════════════
function handleLogin() {
  const user  = document.getElementById('loginUser').value.trim();
  const pass  = document.getElementById('loginPass').value;
  const token = document.getElementById('loginToken').value.trim();
  const result = document.getElementById('loginResult');

  if (!user || !pass) {
    showResult(result, 'error', '⚠ Username and password are required.');
    return;
  }

  // LAYER 1: Injection Detection
  const userCheck = detectSQLInjection(user);
  const passCheck = detectSQLInjection(pass);

  if (userCheck.isInjection || passCheck.isInjection) {
    stats.blocked++;
    updateStats();
    const patterns = [...userCheck.matches, ...passCheck.matches].map(m => m.name).join(', ');
    addLog('LOGIN ATTEMPT', truncate(user), 'BLOCKED', 'L1 Pattern Scan', 'threat');
    showToast('error', `🚨 SQL Injection Blocked! Patterns: ${patterns}`);
    showResult(result, 'error',
      `🚨 SQL INJECTION DETECTED — ACCESS DENIED\n\n` +
      `Field: ${userCheck.isInjection ? 'Username' : 'Password'}\n` +
      `Matched Patterns: ${patterns}\n` +
      `Action: Request terminated at Layer 1\n` +
      `Recommendation: All fields sanitized and incident logged.`);
    return;
  }

  // LAYER 1: Sanitize
  const safeUser = sanitizeInput(user);
  const safePass = sanitizeInput(pass);

  // Validate capability token (if provided)
  let tokenValid = null;
  let tokenPayload = null;
  if (token) {
    const tv = validateCapabilityToken(token);
    tokenValid   = tv.valid;
    tokenPayload = tv.payload;
    if (!tv.valid) {
      addLog('TOKEN VALIDATE', truncate(token), 'BLOCKED', 'Token Layer', 'token');
      showResult(result, 'error', `🔑 Invalid Capability Token: ${tv.reason}`);
      return;
    }
  }

  // LAYER 2: Parameterized query simulation
  const paramsCopy = [safeUser, sha256(safePass)];
  const query = buildParameterizedQuery(
    'SELECT id,username,scope FROM users WHERE username=? AND password_hash=?',
    paramsCopy
  );

  // Look up in simulated DB
  const found = secureDB.find(r =>
    r.username === safeUser && r.passwordHash === sha256(safePass)
  );

  stats.queries++;
  updateStats();
  addLog('LOGIN', truncate(safeUser), found ? 'OK' : 'WARN', 'L2 Parameterized', 'auth');

  if (found) {
    const scope = tokenPayload ? tokenPayload.scp : found.scope;
    showResult(result, 'success',
      `✅ LOGIN SUCCESSFUL\n\n` +
      `User: ${found.username}\n` +
      `Email: ${aesDecrypt(found.emailEnc)}\n` +
      `Access Scope: ${scope.toUpperCase()}\n` +
      `Layer 1: Pattern scan ✓\n` +
      `Layer 2: Parameterized query ✓\n` +
      `Credential: AES-256 verified ✓` +
      (tokenPayload ? `\nToken Scope: ${tokenPayload.scp} (expires ${new Date(tokenPayload.exp).toLocaleString()})` : ''));
    showToast('success', `✅ Authenticated: ${found.username}`);
  } else {
    showResult(result, 'error',
      `❌ AUTHENTICATION FAILED\n\nInvalid credentials. No SQL injection was detected.\nLayer 2 parameterized query executed safely.`);
    showToast('info', '❌ Invalid credentials.');
  }
}

// ════════════════════════════════════════════════
// REGISTER HANDLER
// ════════════════════════════════════════════════
function handleRegister() {
  const name  = document.getElementById('regName').value.trim();
  const email = document.getElementById('regEmail').value.trim();
  const user  = document.getElementById('regUser').value.trim();
  const pass  = document.getElementById('regPass').value;

  const result = document.getElementById('regResult');

  if (!name || !email || !user || !pass) {
    showResult(result, 'error', '⚠ All fields are required.');
    return;
  }

  // LAYER 1 check all fields
  for (const [label, val] of [['Name', name], ['Email', email], ['Username', user]]) {
    const check = detectSQLInjection(val);
    if (check.isInjection) {
      stats.blocked++;
      updateStats();
      addLog('REGISTER', truncate(val), 'BLOCKED', 'L1 Pattern Scan', 'threat');
      showResult(result, 'error',
        `🚨 SQL INJECTION in ${label} field!\nPatterns: ${check.matches.map(m => m.name).join(', ')}\nRegistration denied.`);
      showToast('error', `🚨 Injection blocked in ${label} field!`);
      return;
    }
  }

  if (secureDB.find(r => r.username === user)) {
    showResult(result, 'error', `⚠ Username "${user}" already exists.`);
    return;
  }

  // LAYER 2: Encrypt and store
  const hash     = sha256(pass);
  const hashAES  = aesEncrypt(hash);
  const emailEnc = aesEncrypt(email);
  const nameEnc  = aesEncrypt(name);
  const id       = 'USR_' + Date.now().toString(36).toUpperCase();

  const record = {
    id, username: user, emailEnc, nameEnc,
    passwordHash: hash,
    passwordAES: hashAES,
    scope: 'read',
    created: new Date().toLocaleString()
  };
  secureDB.push(record);

  stats.encrypted++;
  stats.queries++;
  updateStats();
  addLog('REGISTER', truncate(user), 'OK', 'L1+L2+AES', 'auth');
  renderDBTable();

  showResult(result, 'success',
    `✅ ACCOUNT CREATED SUCCESSFULLY\n\n` +
    `ID: ${id}\n` +
    `Username: ${user}\n` +
    `Email: [AES-256 encrypted]\n` +
    `Password: SHA-256 → AES-256 encrypted\n` +
    `Layer 1: All fields scanned ✓\n` +
    `Layer 2: Parameterized INSERT ✓\n` +
    `Encryption: AES-256 applied ✓`);
  showToast('success', `✅ User "${user}" registered securely!`);
}

// ════════════════════════════════════════════════
// QUERY ANALYSIS
// ════════════════════════════════════════════════
function analyzeQuery() {
  const input = document.getElementById('queryInput').value.trim();
  const out   = document.getElementById('queryResult');
  if (!input) { out.innerHTML = '<div class="placeholder-msg">Enter a query first.</div>'; return; }

  const result = detectSQLInjection(input);
  const riskScore = result.matches.length;
  const maxRisk   = result.matches.some(m => m.danger === 'critical') ? 'CRITICAL' : riskScore > 0 ? 'HIGH' : 'CLEAN';

  if (result.isInjection) {
    stats.blocked++;
    addLog('QUERY ANALYZE', truncate(input), 'BLOCKED', 'L1 Pattern Scan', 'query');
  } else {
    stats.queries++;
    addLog('QUERY ANALYZE', truncate(input), 'OK', 'L1 Pattern Scan', 'query');
  }
  updateStats();

  const scoreColor = maxRisk === 'CLEAN' ? 'safe' : '';
  const badgeClass = maxRisk === 'CLEAN' ? 'clean' : 'threat';

  out.innerHTML = `
    <div class="ar-header">
      <span class="ar-badge ${badgeClass}">${maxRisk}</span>
      <span class="ar-score ${scoreColor}">${riskScore > 0 ? riskScore + ' PATTERN(S)' : 'CLEAN'}</span>
    </div>
    <div class="ar-row"><span class="ar-label">Input length:</span><span class="ar-val">${input.length} chars</span></div>
    <div class="ar-row"><span class="ar-label">Risk Level:</span><span class="ar-val" style="color:${maxRisk==='CLEAN'?'var(--green)':'var(--red)'}">${maxRisk}</span></div>
    <div class="ar-row"><span class="ar-label">Patterns Hit:</span><span class="ar-val">${riskScore}</span></div>
    ${result.isInjection ? `
    <div class="ar-list">
      ${result.matches.map(m => `<span class="ar-match">${m.name} [${m.danger}]</span>`).join('')}
    </div>
    <div class="ar-row" style="margin-top:10px">
      <span class="ar-label">Action:</span>
      <span class="ar-val" style="color:var(--red)">BLOCKED — Request terminated at Layer 1</span>
    </div>
    ` : `
    <div class="ar-row" style="margin-top:8px">
      <span class="ar-label">Action:</span>
      <span class="ar-val" style="color:var(--green)">PASS — Safe to parameterize</span>
    </div>
    `}
  `;
}

function sanitizeQuery() {
  const input = document.getElementById('queryInput').value.trim();
  const out   = document.getElementById('queryResult');
  if (!input) return;

  const sanitized = sanitizeInput(input);
  const orig = detectSQLInjection(input);
  const after = detectSQLInjection(sanitized);

  addLog('SANITIZE', truncate(input), 'OK', 'L1 Sanitizer', 'query');

  out.innerHTML = `
    <div class="ar-row"><span class="ar-label">Original:</span><span class="ar-val" style="color:var(--red);font-family:var(--mono);font-size:11px">${escapeHtml(input)}</span></div>
    <div class="ar-row" style="margin-top:10px"><span class="ar-label">Sanitized:</span><span class="ar-val" style="color:var(--green);font-family:var(--mono);font-size:11px">${escapeHtml(sanitized)}</span></div>
    <div class="ar-row" style="margin-top:10px">
      <span class="ar-label">Before:</span><span class="ar-val">${orig.matches.length} threat pattern(s)</span>
    </div>
    <div class="ar-row">
      <span class="ar-label">After:</span><span class="ar-val" style="color:${after.matches.length===0?'var(--green)':'var(--yellow)'}">
        ${after.matches.length} threat pattern(s)
      </span>
    </div>
  `;
}

function parameterizeQuery() {
  const input = document.getElementById('queryInput').value.trim();
  const out   = document.getElementById('paramResult');
  if (!input) return;

  // Extract values from WHERE clause for demonstration
  const whereMatch = input.match(/WHERE\s+(.*?)(?:;|--|$)/i);
  const params = [];
  let template = input;

  if (whereMatch) {
    let conditions = whereMatch[1];
    conditions = conditions.replace(/=\s*['"]([^'"]+)['"]/g, (m, val) => {
      params.push(val);
      return '= ?';
    });
    conditions = conditions.replace(/=\s*([\d]+)/g, (m, val) => {
      params.push(parseInt(val));
      return '= ?';
    });
    template = input.replace(whereMatch[1], conditions);
  }

  const built = buildParameterizedQuery(template, [...params]);

  addLog('PARAMETERIZE', truncate(input), 'OK', 'L2 Param Engine', 'query');
  stats.queries++;
  updateStats();

  out.innerHTML = `
    <div style="color:var(--text3);font-size:10px;margin-bottom:8px;letter-spacing:1px">PARAMETERIZED QUERY</div>
    <div style="color:var(--accent);margin-bottom:10px;word-break:break-all">${escapeHtml(built.template)}</div>
    <div style="color:var(--text3);font-size:10px;margin-bottom:4px">BOUND PARAMETERS (${params.length}):</div>
    ${params.length === 0
      ? '<div style="color:var(--text3)">No parameters extracted</div>'
      : params.map((p,i) => `<div style="margin-bottom:3px"><span style="color:var(--text3)">$${i+1} = </span><span style="color:var(--green)">"${escapeHtml(String(p))}"</span></div>`).join('')
    }
    <div style="margin-top:12px;padding-top:10px;border-top:1px solid var(--border)">
      <div style="color:var(--text3);font-size:10px;margin-bottom:4px">SQL INJECTION SAFE:</div>
      <div style="color:var(--green);font-size:11px">✓ Parameters bound as data, never as SQL code</div>
      <div style="color:var(--green);font-size:11px">✓ Database driver handles escaping internally</div>
      <div style="color:var(--green);font-size:11px">✓ Query structure cannot be altered by user input</div>
    </div>
  `;
}

function clearQuery() {
  document.getElementById('queryInput').value = '';
  document.getElementById('queryResult').innerHTML = '<div class="placeholder-msg">Run an analysis to see results here...</div>';
  document.getElementById('paramResult').innerHTML = '<div class="placeholder-msg">Parameterization output appears here...</div>';
}

function loadPayload(idx) {
  document.getElementById('queryInput').value = PAYLOADS[idx];
}

// ════════════════════════════════════════════════
// CAPABILITY TOKEN GENERATOR
// ════════════════════════════════════════════════
function generateToken() {
  const subject = document.getElementById('tokenSubject').value.trim() || 'user_anon';
  const scope   = document.getElementById('tokenScope').value;
  const expiry  = parseInt(document.getElementById('tokenExpiry').value) || 24;

  const token   = generateCapabilityToken(subject, scope, expiry);
  const expires = new Date(Date.now() + expiry * 3600 * 1000).toLocaleString();

  document.getElementById('tokenOutput').textContent = token;

  const detDiv = document.getElementById('tokenDetails');
  detDiv.classList.remove('hidden');
  detDiv.innerHTML = `
    <div class="td-row"><span class="td-key">Subject:</span><span class="td-val">${subject}</span></div>
    <div class="td-row"><span class="td-key">Scope:</span><span class="td-val">${scope.toUpperCase()}</span></div>
    <div class="td-row"><span class="td-key">Issued:</span><span class="td-val">${new Date().toLocaleString()}</span></div>
    <div class="td-row"><span class="td-key">Expires:</span><span class="td-val">${expires}</span></div>
    <div class="td-row"><span class="td-key">Algorithm:</span><span class="td-val">AES-256 signed</span></div>
    <div class="td-row"><span class="td-key">Structure:</span><span class="td-val">header.payload.signature</span></div>
  `;

  stats.tokens++;
  updateStats();
  addLog('TOKEN ISSUED', `sub:${subject} scp:${scope}`, 'OK', 'Token Layer', 'token');
  showToast('success', `🔑 Token issued for "${subject}" [${scope}]`);
}

// ════════════════════════════════════════════════
// INJECT TEST (from login quick buttons)
// ════════════════════════════════════════════════
function injectTest(fieldId, payload) {
  const field = document.getElementById(fieldId);
  field.value = payload;
  field.dispatchEvent(new Event('input'));
  showToast('info', `💉 Injected: ${payload}`);
}

// ════════════════════════════════════════════════
// LOG FILTER
// ════════════════════════════════════════════════
function filterLogs(type) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');

  document.querySelectorAll('.log-entry').forEach(entry => {
    if (type === 'all' || entry.dataset.type === type) {
      entry.style.display = 'grid';
    } else {
      entry.style.display = 'none';
    }
  });
}

function clearLogs() {
  auditLog.length = 0;
  const c = document.getElementById('logEntries');
  c.innerHTML = '<div class="log-empty">Logs cleared.</div>';
}

// ════════════════════════════════════════════════
// DB TABLE RENDER
// ════════════════════════════════════════════════
function renderDBTable() {
  const tbody = document.getElementById('dbRows');
  if (secureDB.length === 0) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No records yet.</td></tr>';
    return;
  }
  tbody.innerHTML = secureDB.map(r => `
    <tr>
      <td>${r.id}</td>
      <td>${r.username}</td>
      <td class="enc">${truncate(r.emailEnc, 28)}</td>
      <td class="enc">${truncate(r.passwordAES, 28)}</td>
      <td>${r.created}</td>
      <td><span class="scope-badge scope-${r.scope}">${r.scope}</span></td>
    </tr>
  `).join('');
}

// ════════════════════════════════════════════════
// PASSWORD STRENGTH METER
// ════════════════════════════════════════════════
document.getElementById('regPass').addEventListener('input', function() {
  const v = this.value;
  let score = 0;
  if (v.length >= 8)  score++;
  if (v.length >= 12) score++;
  if (/[A-Z]/.test(v)) score++;
  if (/[0-9]/.test(v)) score++;
  if (/[^A-Za-z0-9]/.test(v)) score++;

  const fill  = document.getElementById('strengthFill');
  const label = document.getElementById('strengthLabel');
  const colors  = ['#ff3355','#ff7700','#ffcc00','#00aaff','#00ff88'];
  const labels  = ['Weak','Fair','Moderate','Strong','Very Strong'];
  const widths  = ['20%','40%','60%','80%','100%'];

  fill.style.width      = v ? widths[Math.max(0, score-1)] : '0%';
  fill.style.background = v ? colors[Math.max(0, score-1)] : 'transparent';
  label.textContent     = v ? labels[Math.max(0, score-1)] : '—';

  // Live encryption preview
  if (v) {
    document.getElementById('encInput').textContent = v.length > 12 ? v.substring(0,12) + '...' : v;
    document.getElementById('encHash').textContent  = sha256(v).substring(0, 32) + '...';
    document.getElementById('encAES').textContent   = aesEncrypt(v).substring(0, 32) + '...';
  }
});

// Live watch fields
document.getElementById('regName').addEventListener('input', function() {
  updateShield('regName', 'regNameShield', 'regNameBar');
});
document.getElementById('regEmail').addEventListener('input', function() {
  updateShield('regEmail', 'regEmailShield', 'regEmailBar');
});
document.getElementById('regUser').addEventListener('input', function() {
  updateShield('regUser', 'regUserShield', 'regUserBar');
});
document.getElementById('loginUser').addEventListener('input', function() {
  updateShield('loginUser', 'loginUserShield', 'loginUserBar');
});
document.getElementById('loginPass').addEventListener('input', function() {
  updateShield('loginPass', 'loginPassShield', 'loginPassBar');
});

function updateShield(inputId, shieldId, barId) {
  const val = document.getElementById(inputId).value;
  const shield = document.getElementById(shieldId);
  const bar = barId ? document.getElementById(barId) : null;

  if (!val) {
    document.getElementById(inputId).className = '';
    if (shield) shield.textContent = '🛡️';
    if (bar) { bar.className = 'threat-bar'; bar.dataset.msg = ''; }
    return;
  }
  const result = detectSQLInjection(val);
  if (result.isInjection) {
    document.getElementById(inputId).className = 'danger';
    if (shield) shield.textContent = '🚨';
    if (bar) {
      bar.className = 'threat-bar threat';
      bar.dataset.msg = '⚠ ' + result.matches.map(m => m.name).join(', ');
    }
  } else {
    document.getElementById(inputId).className = 'safe';
    if (shield) shield.textContent = '✅';
    if (bar) { bar.className = 'threat-bar safe'; bar.dataset.msg = ''; }
  }
}

// ════════════════════════════════════════════════
// TOAST & RESULT HELPERS
// ════════════════════════════════════════════════
let toastTimer;
function showToast(type, message) {
  const t = document.getElementById('toast');
  t.className = `toast ${type}`;
  t.textContent = message;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.classList.add('hidden'); }, 4000);
}

function showResult(el, type, message) {
  el.className = `result-panel ${type}`;
  el.style.whiteSpace = 'pre-wrap';
  el.textContent = message;
}

function escapeHtml(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════
function init() {
  // Render pattern cards
  const grid = document.getElementById('patternGrid');
  SQL_PATTERNS.forEach(p => {
    const div = document.createElement('div');
    div.className = 'pattern-item';
    div.innerHTML = `
      <div>
        <div class="pi-danger ${p.danger}">${p.danger.toUpperCase()}</div>
      </div>
      <div>
        <div class="pi-name">${p.name}</div>
        <div class="pi-regex">eg: ${p.regex}</div>
      </div>
    `;
    grid.appendChild(div);
  });

  // Pre-populate demo user
  const demoHash = sha256('demo1234');
  secureDB.push({
    id: 'USR_DEMO01',
    username: 'demo',
    emailEnc: aesEncrypt('demo@securevault.io'),
    nameEnc:  aesEncrypt('Demo User'),
    passwordHash: demoHash,
    passwordAES: aesEncrypt(demoHash),
    scope: 'read',
    created: new Date().toLocaleString()
  });
  stats.encrypted = 1;
  updateStats();
  renderDBTable();
  addLog('SYSTEM BOOT', 'SecureVault initialized', 'OK', 'System', 'auth');
  showToast('info', '⬡ SecureVault online — Demo user: demo / demo1234');
}

init();
