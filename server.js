/**
 * GRE Word App - Sync Backend v2
 * Node.js + Express + JSON File Storage + JWT
 * Admin API included — no native dependencies, runs on Render free tier
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'greword-secret-key-change-in-production';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'greword2024admin';
const SERVER_START_TIME = Date.now();

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Request logging (lightweight)
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    if (req.path.startsWith('/api/admin')) {
      const duration = Date.now() - start;
      logActivity('api_call', {
        method: req.method,
        path: req.path,
        status: res.statusCode,
        duration
      });
    }
  });
  next();
});

// Ensure data directory exists (Render provides persistent disk at /data)
const DATA_DIR = process.env.RENDER_DISK_MOUNT_PATH || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PROGRESS_DIR = path.join(DATA_DIR, 'progress');
const LOGS_DIR = path.join(DATA_DIR, 'logs');
const ACTIVITY_FILE = path.join(DATA_DIR, 'activity.json');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');

// Ensure subdirectories exist
if (!fs.existsSync(PROGRESS_DIR)) fs.mkdirSync(PROGRESS_DIR, { recursive: true });
if (!fs.existsSync(LOGS_DIR)) fs.mkdirSync(LOGS_DIR, { recursive: true });
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

// --- Helper functions ---
function readJSON(filePath, defaultValue = []) {
  try {
    if (!fs.existsSync(filePath)) return defaultValue;
    const data = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(data);
  } catch {
    return defaultValue;
  }
}

function writeJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

function getNextId(items) {
  if (items.length === 0) return 1;
  return Math.max(...items.map(i => i.id || 0)) + 1;
}

// --- Activity Log ---
function logActivity(type, detail = {}) {
  try {
    const logs = readJSON(ACTIVITY_FILE, []);
    logs.push({
      id: logs.length + 1,
      type,
      detail,
      timestamp: new Date().toISOString()
    });
    // Keep last 500 entries
    if (logs.length > 500) logs.splice(0, logs.length - 500);
    writeJSON(ACTIVITY_FILE, logs);
  } catch {}
}

function getActivityLogs(limit = 50) {
  const logs = readJSON(ACTIVITY_FILE, []);
  return logs.slice(-limit).reverse();
}

// --- Users ---
function getUsers() {
  return readJSON(USERS_FILE, []);
}

function saveUsers(users) {
  writeJSON(USERS_FILE, users);
}

function getUserByEmail(email) {
  return getUsers().find(u => u.email === email);
}

function getUserById(id) {
  return getUsers().find(u => u.id === id);
}

function createUser(email, password) {
  const users = getUsers();
  const newUser = {
    id: getNextId(users),
    email,
    password_hash: bcrypt.hashSync(password, 10),
    disabled: false,
    created_at: new Date().toISOString()
  };
  users.push(newUser);
  saveUsers(users);
  logActivity('user_register', { userId: newUser.id, email });
  return newUser;
}

// --- Progress ---
function getProgressFile(userId) {
  return path.join(PROGRESS_DIR, `user_${userId}.json`);
}

function getUserProgress(userId) {
  return readJSON(getProgressFile(userId), {});
}

function saveUserProgress(userId, progress) {
  writeJSON(getProgressFile(userId), progress);
}

// --- Logs ---
function getLogsFile(userId) {
  return path.join(LOGS_DIR, `user_${userId}.json`);
}

function getUserLogs(userId) {
  return readJSON(getLogsFile(userId), {});
}

function saveUserLogs(userId, logs) {
  writeJSON(getLogsFile(userId), logs);
}

// JWT middleware
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.substring(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.userEmail = decoded.email;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Admin auth middleware — supports both header and body password
function verifyAdmin(req, res, next) {
  // Try header first: Authorization: Bearer admin:<password>
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    if (token.startsWith('admin:') && token.substring(6) === ADMIN_PASSWORD) {
      return next();
    }
  }
  // Fallback to body password
  const { password } = req.body || {};
  if (password === ADMIN_PASSWORD) {
    return next();
  }
  return res.status(401).json({ error: 'Invalid admin password' });
}

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ========== AUTH ENDPOINTS ==========

// Register
app.post('/api/auth/register', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    let user = getUserByEmail(email);

    if (user) {
      // Account exists: update password (allow re-register to reset)
      const users = getUsers();
      const idx = users.findIndex(u => u.id === user.id);
      users[idx].password_hash = bcrypt.hashSync(password, 10);
      saveUsers(users);
      user = users[idx];
      logActivity('user_reregister', { userId: user.id, email });
    } else {
      user = createUser(email, password);
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      success: true,
      token,
      user: { id: user.id, email: user.email }
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const user = getUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (user.disabled) {
      return res.status(403).json({ error: 'Account disabled' });
    }

    if (!bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    logActivity('user_login', { userId: user.id, email });

    res.json({
      success: true,
      token,
      user: { id: user.id, email: user.email }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
app.get('/api/auth/me', verifyToken, (req, res) => {
  res.json({
    success: true,
    user: { id: req.userId, email: req.userEmail }
  });
});

// ========== SYNC ENDPOINTS ==========

// Full sync (upload progress + logs)
app.post('/api/sync/full', verifyToken, (req, res) => {
  try {
    const { progress, logs } = req.body;
    const userId = req.userId;
    let updatedProgress = 0;
    let updatedLogs = 0;

    // Check if user is disabled
    const user = getUserById(userId);
    if (user && user.disabled) {
      return res.status(403).json({ error: 'Account disabled' });
    }

    // Merge progress
    if (progress && Array.isArray(progress)) {
      const existing = getUserProgress(userId);
      for (const item of progress) {
        const key = item.word_id;
        if (!existing[key] || (item.updated_at && existing[key].updated_at < item.updated_at)) {
          existing[key] = {
            interval: item.interval || 0,
            ease_factor: item.ease_factor || 2.5,
            repetitions: item.repetitions || 0,
            next_review: item.next_review || 0,
            last_review: item.last_review || 0,
            mistake_count: item.mistake_count || 0,
            updated_at: item.updated_at || Date.now()
          };
          updatedProgress++;
        }
      }
      saveUserProgress(userId, existing);
    }

    // Merge logs
    if (logs && Array.isArray(logs)) {
      const existing = getUserLogs(userId);
      for (const item of logs) {
        const key = item.date;
        if (!existing[key] || (item.updated_at && existing[key].updated_at < item.updated_at)) {
          existing[key] = {
            study_count: item.study_count || 0,
            correct_count: item.correct_count || 0,
            mistake_count: item.mistake_count || 0,
            updated_at: item.updated_at || Date.now()
          };
          updatedLogs++;
        }
      }
      saveUserLogs(userId, existing);
    }

    if (updatedProgress > 0 || updatedLogs > 0) {
      logActivity('user_sync', { userId, updatedProgress, updatedLogs });
    }

    res.json({
      success: true,
      message: 'Sync completed',
      updatedProgress,
      updatedLogs
    });
  } catch (err) {
    console.error('Sync error:', err);
    res.status(500).json({ error: 'Sync failed', details: err.message });
  }
});

// Download progress
app.get('/api/sync/progress', verifyToken, (req, res) => {
  try {
    const data = getUserProgress(req.userId);
    const progress = Object.entries(data).map(([word_id, v]) => ({
      word_id,
      interval: v.interval,
      ease_factor: v.ease_factor,
      repetitions: v.repetitions,
      next_review: v.next_review,
      last_review: v.last_review,
      mistake_count: v.mistake_count,
      updated_at: v.updated_at
    }));
    res.json({ success: true, progress });
  } catch (err) {
    console.error('Get progress error:', err);
    res.status(500).json({ error: 'Failed to get progress' });
  }
});

// Download logs
app.get('/api/sync/logs', verifyToken, (req, res) => {
  try {
    const data = getUserLogs(req.userId);
    const logs = Object.entries(data).map(([date, v]) => ({
      date,
      study_count: v.study_count,
      correct_count: v.correct_count,
      mistake_count: v.mistake_count,
      updated_at: v.updated_at
    }));
    res.json({ success: true, logs });
  } catch (err) {
    console.error('Get logs error:', err);
    res.status(500).json({ error: 'Failed to get logs' });
  }
});

// ========== ADMIN ENDPOINTS ==========

// Admin login — returns a session token for subsequent calls
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) {
    logActivity('admin_login_failed', { ip: req.ip });
    return res.status(401).json({ error: 'Invalid admin password' });
  }
  logActivity('admin_login', {});
  res.json({
    success: true,
    token: `admin:${ADMIN_PASSWORD}`,
    message: 'Admin authenticated'
  });
});

// Admin stats
app.post('/api/admin/stats', verifyAdmin, (req, res) => {
  try {
    const users = getUsers();
    const totalUsers = users.length;
    const activeUsers = users.filter(u => !u.disabled).length;
    const disabledUsers = users.filter(u => u.disabled).length;

    let totalProgressSize = 0;
    let totalLogsSize = 0;
    let totalSyncs = 0;
    let totalUsersFileSize = 0;

    // Users file size
    if (fs.existsSync(USERS_FILE)) {
      totalUsersFileSize = fs.statSync(USERS_FILE).size;
    }

    if (fs.existsSync(PROGRESS_DIR)) {
      const progressFiles = fs.readdirSync(PROGRESS_DIR);
      for (const file of progressFiles) {
        const filePath = path.join(PROGRESS_DIR, file);
        const stats = fs.statSync(filePath);
        totalProgressSize += stats.size;
        try {
          const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
          totalSyncs += Object.keys(data).length;
        } catch {}
      }
    }

    if (fs.existsSync(LOGS_DIR)) {
      const logFiles = fs.readdirSync(LOGS_DIR);
      for (const file of logFiles) {
        const filePath = path.join(LOGS_DIR, file);
        const stats = fs.statSync(filePath);
        totalLogsSize += stats.size;
      }
    }

    // Recent users (last 10 registered)
    const recentUsers = [...users]
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
      .slice(0, 10)
      .map(u => ({ id: u.id, email: u.email, created_at: u.created_at, disabled: !!u.disabled }));

    const diskUsageBytes = totalUsersFileSize + totalProgressSize + totalLogsSize;
    const diskUsageMB = (diskUsageBytes / (1024 * 1024)).toFixed(2);

    res.json({
      success: true,
      stats: {
        totalUsers,
        activeUsers,
        disabledUsers,
        totalSyncs,
        diskUsageMB: parseFloat(diskUsageMB),
        diskUsageBytes,
        progressFiles: fs.existsSync(PROGRESS_DIR) ? fs.readdirSync(PROGRESS_DIR).length : 0,
        logFiles: fs.existsSync(LOGS_DIR) ? fs.readdirSync(LOGS_DIR).length : 0,
        recentUsers,
        serverUptime: Math.floor(process.uptime()),
        timestamp: new Date().toISOString()
      }
    });
  } catch (err) {
    console.error('Admin stats error:', err);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

// Admin: list all users with search & sort
app.post('/api/admin/users', verifyAdmin, (req, res) => {
  try {
    const { search, sort = 'id', order = 'asc' } = req.body || {};
    const users = getUsers();

    let userList = users.map(u => {
      const progressFile = getProgressFile(u.id);
      const logsFile = getLogsFile(u.id);
      let wordCount = 0;
      let logCount = 0;
      let lastSyncAt = null;

      try {
        if (fs.existsSync(progressFile)) {
          const data = JSON.parse(fs.readFileSync(progressFile, 'utf8'));
          wordCount = Object.keys(data).length;
          // Find last sync time
          const times = Object.values(data).map(v => v.updated_at || 0);
          if (times.length > 0) lastSyncAt = new Date(Math.max(...times)).toISOString();
        }
        if (fs.existsSync(logsFile)) {
          const data = JSON.parse(fs.readFileSync(logsFile, 'utf8'));
          logCount = Object.keys(data).length;
        }
      } catch {}

      return {
        id: u.id,
        email: u.email,
        created_at: u.created_at,
        disabled: !!u.disabled,
        wordCount,
        logCount,
        lastSyncAt
      };
    });

    // Search filter
    if (search) {
      const q = search.toLowerCase();
      userList = userList.filter(u => u.email.toLowerCase().includes(q) || String(u.id).includes(q));
    }

    // Sort
    const validSorts = ['id', 'email', 'created_at', 'wordCount', 'logCount', 'lastSyncAt'];
    const sortKey = validSorts.includes(sort) ? sort : 'id';
    userList.sort((a, b) => {
      let va = a[sortKey], vb = b[sortKey];
      if (typeof va === 'string') va = va.toLowerCase();
      if (typeof vb === 'string') vb = vb.toLowerCase();
      if (va === null || va === undefined) va = order === 'asc' ? '' : 0;
      if (vb === null || vb === undefined) vb = order === 'asc' ? '' : 0;
      if (va < vb) return order === 'asc' ? -1 : 1;
      if (va > vb) return order === 'asc' ? 1 : -1;
      return 0;
    });

    res.json({ success: true, users: userList, total: userList.length });
  } catch (err) {
    console.error('Admin users error:', err);
    res.status(500).json({ error: 'Failed to get users' });
  }
});

// Admin: get single user detail
app.post('/api/admin/user/:id', verifyAdmin, (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const user = getUserById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const progress = getUserProgress(userId);
    const logs = getUserLogs(userId);

    // Progress summary
    const progressEntries = Object.entries(progress);
    const totalWords = progressEntries.length;
    let mastered = 0, learning = 0, newWords = 0;
    for (const [, v] of progressEntries) {
      if (v.repetitions >= 5) mastered++;
      else if (v.repetitions >= 1) learning++;
      else newWords++;
    }

    // Log summary
    const logEntries = Object.entries(logs);
    let totalStudy = 0, totalCorrect = 0, totalMistake = 0;
    for (const [, v] of logEntries) {
      totalStudy += v.study_count || 0;
      totalCorrect += v.correct_count || 0;
      totalMistake += v.mistake_count || 0;
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        created_at: user.created_at,
        disabled: !!user.disabled
      },
      progress: {
        totalWords,
        mastered,
        learning,
        newWords,
        accuracy: totalCorrect + totalMistake > 0
          ? Math.round(totalCorrect / (totalCorrect + totalMistake) * 100)
          : 0
      },
      logs: {
        totalDays: logEntries.length,
        totalStudy,
        totalCorrect,
        totalMistake
      },
      recentProgress: progressEntries
        .sort(([, a], [, b]) => (b.updated_at || 0) - (a.updated_at || 0))
        .slice(0, 20)
        .map(([word_id, v]) => ({ word_id, ...v })),
      recentLogs: logEntries
        .sort(([, a], [, b]) => (b.updated_at || 0) - (a.updated_at || 0))
        .slice(0, 20)
        .map(([date, v]) => ({ date, ...v }))
    });
  } catch (err) {
    console.error('Admin user detail error:', err);
    res.status(500).json({ error: 'Failed to get user detail' });
  }
});

// Admin: delete user
app.post('/api/admin/user/:id/delete', verifyAdmin, (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const users = getUsers();
    const idx = users.findIndex(u => u.id === userId);
    if (idx === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    const deleted = users.splice(idx, 1)[0];
    saveUsers(users);

    // Delete progress & logs files
    const pf = getProgressFile(userId);
    const lf = getLogsFile(userId);
    if (fs.existsSync(pf)) fs.unlinkSync(pf);
    if (fs.existsSync(lf)) fs.unlinkSync(lf);

    logActivity('user_deleted', { userId, email: deleted.email });
    res.json({ success: true, message: `User ${deleted.email} deleted` });
  } catch (err) {
    console.error('Admin delete user error:', err);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Admin: disable user
app.post('/api/admin/user/:id/disable', verifyAdmin, (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const users = getUsers();
    const user = users.find(u => u.id === userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.disabled = true;
    saveUsers(users);
    logActivity('user_disabled', { userId, email: user.email });
    res.json({ success: true, message: `User ${user.email} disabled` });
  } catch (err) {
    console.error('Admin disable user error:', err);
    res.status(500).json({ error: 'Failed to disable user' });
  }
});

// Admin: enable user
app.post('/api/admin/user/:id/enable', verifyAdmin, (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const users = getUsers();
    const user = users.find(u => u.id === userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.disabled = false;
    saveUsers(users);
    logActivity('user_enabled', { userId, email: user.email });
    res.json({ success: true, message: `User ${user.email} enabled` });
  } catch (err) {
    console.error('Admin enable user error:', err);
    res.status(500).json({ error: 'Failed to enable user' });
  }
});

// Admin: reset user password
app.post('/api/admin/user/:id/reset-password', verifyAdmin, (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const users = getUsers();
    const user = users.find(u => u.id === userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.password_hash = bcrypt.hashSync(newPassword, 10);
    saveUsers(users);
    logActivity('user_password_reset', { userId, email: user.email });
    res.json({ success: true, message: `Password reset for ${user.email}` });
  } catch (err) {
    console.error('Admin reset password error:', err);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Admin: activity log
app.post('/api/admin/activity', verifyAdmin, (req, res) => {
  try {
    const { limit = 50, type } = req.body || {};
    let logs = getActivityLogs(limit);
    if (type) {
      logs = logs.filter(l => l.type === type);
    }
    res.json({ success: true, logs });
  } catch (err) {
    console.error('Admin activity error:', err);
    res.status(500).json({ error: 'Failed to get activity log' });
  }
});

// Admin: system info
app.post('/api/admin/system', verifyAdmin, (req, res) => {
  try {
    const memUsage = process.memoryUsage();
    const uptime = process.uptime();

    res.json({
      success: true,
      system: {
        nodeVersion: process.version,
        platform: process.platform,
        uptime: Math.floor(uptime),
        uptimeFormatted: formatUptime(uptime),
        memory: {
          rss: formatBytes(memUsage.rss),
          heapTotal: formatBytes(memUsage.heapTotal),
          heapUsed: formatBytes(memUsage.heapUsed),
          external: formatBytes(memUsage.external)
        },
        dataDir: DATA_DIR,
        diskUsage: getDirSize(DATA_DIR),
        serverStartTime: new Date(SERVER_START_TIME).toISOString()
      }
    });
  } catch (err) {
    console.error('Admin system error:', err);
    res.status(500).json({ error: 'Failed to get system info' });
  }
});

// Admin: trigger backup
app.post('/api/admin/backup', verifyAdmin, (req, res) => {
  try {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = path.join(BACKUP_DIR, `backup-${timestamp}`);

    if (!fs.existsSync(backupPath)) fs.mkdirSync(backupPath, { recursive: true });

    // Copy users.json
    if (fs.existsSync(USERS_FILE)) {
      fs.copyFileSync(USERS_FILE, path.join(backupPath, 'users.json'));
    }

    // Copy progress dir
    const progressBackup = path.join(backupPath, 'progress');
    if (!fs.existsSync(progressBackup)) fs.mkdirSync(progressBackup, { recursive: true });
    if (fs.existsSync(PROGRESS_DIR)) {
      for (const file of fs.readdirSync(PROGRESS_DIR)) {
        fs.copyFileSync(path.join(PROGRESS_DIR, file), path.join(progressBackup, file));
      }
    }

    // Copy logs dir
    const logsBackup = path.join(backupPath, 'logs');
    if (!fs.existsSync(logsBackup)) fs.mkdirSync(logsBackup, { recursive: true });
    if (fs.existsSync(LOGS_DIR)) {
      for (const file of fs.readdirSync(LOGS_DIR)) {
        fs.copyFileSync(path.join(LOGS_DIR, file), path.join(logsBackup, file));
      }
    }

    // Cleanup old backups (keep last 5)
    const backups = fs.readdirSync(BACKUP_DIR)
      .filter(d => d.startsWith('backup-'))
      .sort();
    while (backups.length > 5) {
      const old = backups.shift();
      const oldPath = path.join(BACKUP_DIR, old);
      fs.rmSync(oldPath, { recursive: true, force: true });
    }

    logActivity('backup_created', { path: backupPath });
    res.json({ success: true, message: 'Backup created', backup: backupPath });
  } catch (err) {
    console.error('Admin backup error:', err);
    res.status(500).json({ error: 'Failed to create backup' });
  }
});

// Utility functions
function formatUptime(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}天${h}小时`;
  if (h > 0) return `${h}小时${m}分钟`;
  return `${m}分钟`;
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(2) + ' MB';
}

function getDirSize(dirPath) {
  let totalSize = 0;
  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      if (entry.isFile()) {
        totalSize += fs.statSync(fullPath).size;
      } else if (entry.isDirectory()) {
        totalSize += getDirSize(fullPath);
      }
    }
  } catch {}
  return formatBytes(totalSize);
}

// Start server
app.listen(PORT, () => {
  console.log(`GRE Word Backend v2 running on port ${PORT}`);
  console.log(`Data directory: ${DATA_DIR}`);
  console.log(`Admin endpoints: enabled`);
});
