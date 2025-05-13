const express = require('express');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { google } = require('googleapis');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');
const cron = require('node-cron');
const path = require('path');
const fs = require('fs');
const axios = require('axios');

const app = express();
const port = process.env.PORT || 3000;

// Environment Variables
const {
  APP_EMAIL, APP_PASSWORD, AFFILIATES_SHEET_ID, ADMIN_SHEET_ID,
  GOOGLE_CREDENTIALS, AFFILIATE_API_KEY, JWT_SECRET,
  BOT_STORE_API_URL, BOT_STORE_API_KEY
} = process.env;

// Validate Environment Variables
const validateEnv = () => {
  try {
    if (!APP_EMAIL || !APP_PASSWORD || !AFFILIATES_SHEET_ID || !ADMIN_SHEET_ID || 
        !AFFILIATE_API_KEY || !JWT_SECRET || !BOT_STORE_API_URL || !BOT_STORE_API_KEY) {
      throw new Error('Missing environment variables');
    }
    let credentials;
    try {
      credentials = JSON.parse(GOOGLE_CREDENTIALS);
    } catch {
      const stripped = GOOGLE_CREDENTIALS.replace(/^"|"$/g, '').replace(/\\"/g, '"');
      credentials = JSON.parse(stripped);
    }
    if (!credentials.client_email || !credentials.private_key) {
      throw new Error('GOOGLE_CREDENTIALS missing required fields: client_email or private_key');
    }
    return credentials;
  } catch (err) {
    console.error('Environment validation failed:', err.message);
    process.exit(1);
  }
};
const credentials = validateEnv();

// Middleware
app.use(express.json());
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

// Debug: Log static file requests
app.use((req, res, next) => {
  if (req.path.endsWith('.html')) {
    console.log(`Request for ${req.path}: Attempting to serve from ${publicPath}`);
    const filePath = path.join(publicPath, req.path);
    if (fs.existsSync(filePath)) {
      console.log(`Serving ${filePath}`);
    } else {
      console.log(`File not found: ${filePath}`);
    }
  }
  next();
});

// Rate Limiting
// Use user email or username to rate limit instead of IP
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5,
  keyGenerator: (req) => req.body?.email || req.ip
});
const registerLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.body?.email || req.ip
});
const resetLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.body?.email || req.ip
});

// Google Sheets Setup
const sheets = google.sheets({ version: 'v4', auth: new google.auth.JWT({
  email: credentials.client_email,
  key: credentials.private_key,
  scopes: ['https://www.googleapis.com/auth/spreadsheets']
}) });

const initializeSheets = async () => {
  try {
    const getSheetTabs = async (spreadsheetId) => {
      const response = await sheets.spreadsheets.get({ spreadsheetId });
      return response.data.sheets.map(sheet => sheet.properties.title);
    };

    const createTab = async (spreadsheetId, tabName) => {
      await sheets.spreadsheets.batchUpdate({
        spreadsheetId,
        resource: {
          requests: [{
            addSheet: {
              properties: { title: tabName }
            }
          }]
        }
      });
      console.log(`Created tab '${tabName}' in spreadsheet ${spreadsheetId}`);
    };

    const affiliatesHeaders = [
      'Email', 'Username', 'Name', 'JoinDate', 'RefCode', 'Password',
      'Statusjson', 'LinkClicks', 'TotalSales', 'TotalSalesMonthly',
      'CurrentBalance', 'WithdrawnTotal', 'WithdrawalsJSON', 'RewardsJSON',
      'NotificationsJSON', 'MpesaDetails'
    ];
    let affiliateTabs = await getSheetTabs(AFFILIATES_SHEET_ID);
    if (!affiliateTabs.includes('all affiliates')) {
      await createTab(AFFILIATES_SHEET_ID, 'all affiliates');
    }
    if (!affiliateTabs.includes('transactionLog')) {
      await createTab(AFFILIATES_SHEET_ID, 'transactionLog');
      await sheets.spreadsheets.values.update({
        spreadsheetId: AFFILIATES_SHEET_ID,
        range: 'transactionLog!A1:C1',
        valueInputOption: 'RAW',
        resource: { values: [['Timestamp', 'Email', 'Action']] }
      });
    }
    await sheets.spreadsheets.values.update({
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: 'all affiliates!A1:P1',
      valueInputOption: 'RAW',
      resource: { values: [affiliatesHeaders] }
    });
    console.log('Initialized headers for all affiliates tab');

    const settingsData = [
      ['supportEmail', 'derivbotstore@gmail.com'],
      ['copyrightText', 'Deriv Bot Store Affiliates 2025'],
      ['whatsappLink', 'https://wa.link/4wppln'],
      ['commissionRate', '0.2'],
      ['logoUrl', ''],
      ['adminEmail', 'admin@botblitz.store'],
      ['adminPassword', 'kaylie2025'],
      ['urgentPopup', JSON.stringify({ message: '', enabled: false })]
    ];
    let adminTabs = await getSheetTabs(ADMIN_SHEET_ID);
    if (!adminTabs.includes('settingsAffiliate')) {
      await createTab(ADMIN_SHEET_ID, 'settingsAffiliate');
    }
    await sheets.spreadsheets.values.update({
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'settingsAffiliate!A1:B8',
      valueInputOption: 'RAW',
      resource: { values: settingsData }
    });
    console.log('Initialized settingsAffiliate tab');

    const adminTabsConfig = [
      { name: 'staticPagesAffiliate', headers: ['Slug', 'Title', 'Content'] },
      { name: 'pendingWithdrawals', headers: ['Email', 'Name', 'Timestamp', 'Amount', 'MpesaNumber', 'MpesaName', 'PaymentRefcode', 'Status'] },
      { name: 'sortedWithdrawals', headers: ['Email', 'Name', 'Timestamp', 'Amount', 'MpesaNumber', 'MpesaName', 'PaymentRefcode', 'Status'] },
      { name: 'reset', headers: ['Email', 'Username', 'Name', 'LastWithdrawalAmount', 'Description', 'Timestamp', 'Status', 'Password'] },
      { name: 'News', headers: ['Id', 'Message', 'Timestamp'] }
    ];
    for (const tab of adminTabsConfig) {
      if (!adminTabs.includes(tab.name)) {
        await createTab(ADMIN_SHEET_ID, tab.name);
      }
      await sheets.spreadsheets.values.update({
        spreadsheetId: ADMIN_SHEET_ID,
        range: `${tab.name}!A1:${String.fromCharCode(65 + tab.headers.length - 1)}1`,
        valueInputOption: 'RAW',
        resource: { values: [tab.headers] }
      });
      console.log(`Initialized headers for ${tab.name} tab`);
    }

    console.log('Google Sheets fully initialized');
  } catch (err) {
    console.error('Failed to initialize sheets:', err.message);
    if (err.code === 403) {
      console.error('Permission denied: Ensure the Service Account has Editor access to both Sheets');
    } else if (err.code === 404) {
      console.error('Sheet not found: Verify AFFILIATES_SHEET_ID and ADMIN_SHEET_ID');
    }
    process.exit(1);
  }
};

// Cache
let cachedDataAffiliate = {
  affiliates: [],
  settings: {},
  staticPages: []
};
let leaderboardCache = {};

// Transaction Logging
async function logTransaction(email, action, details) {
  try {
    await sheets.spreadsheets.values.append({
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: 'transactionLog!A:C',
      valueInputOption: 'RAW',
      resource: {
        values: [[new Date().toISOString(), email, `${action}: ${JSON.stringify(details)}`]],
      },
    });
    console.log(`Logged transaction for ${email}: ${action}`);
  } catch (error) {
    console.error('Error logging transaction:', error.message);
  }
}

// Fetch and Cache Data
const fetchAffiliates = async () => {
  const response = await sheets.spreadsheets.values.get({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: 'all affiliates!A2:P'
  });
  const rows = response.data.values || [];
  return rows.map(row => ({
    Email: row[0],
    Username: row[1],
    Name: row[2],
    JoinDate: row[3],
    RefCode: row[4],
    Password: row[5],
    Statusjson: JSON.parse(row[6] || '{}'),
    LinkClicks: parseInt(row[7] || '0'),
    TotalSales: parseInt(row[8] || '0'),
    TotalSalesMonthly: parseInt(row[9] || '0'),
    CurrentBalance: parseFloat(row[10] || '0'),
    WithdrawnTotal: parseFloat(row[11] || '0'),
    WithdrawalsJSON: JSON.parse(row[12] || '[]'),
    RewardsJSON: JSON.parse(row[13] || '[]'),
    NotificationsJSON: JSON.parse(row[14] || '[]'),
    MpesaDetails: JSON.parse(row[15] || '{}')
  }));
};

const fetchSettings = async () => {
  const response = await sheets.spreadsheets.values.get({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'settingsAffiliate!A2:B'
  });
  const rows = response.data.values || [];
  const settings = {};
  rows.forEach(([key, value]) => {
    settings[key] = key === 'urgentPopup' || key === 'commissionRate' ? JSON.parse(value) : value;
  });
  return settings;
};

const fetchStaticPages = async () => {
  const response = await sheets.spreadsheets.values.get({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'staticPagesAffiliate!A2:C'
  });
  const rows = response.data.values || [];
  return rows.map(row => ({ Slug: row[0], Title: row[1], Content: row[2] }));
};

const updateCache = async () => {
  cachedDataAffiliate.affiliates = await fetchAffiliates();
  cachedDataAffiliate.settings = await fetchSettings();
  cachedDataAffiliate.staticPages = await fetchStaticPages();
  console.log('Cache updated');
};

// WebSocket Setup
const wss = new WebSocket.Server({ noServer: true });
const wsClients = new Map();

const validateWebSocket = (token) => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded;
  } catch {
    return null;
  }
};

// WebSocket Heartbeat
function startHeartbeat(ws, key) {
  ws.isAlive = true;
  ws.pingInterval = setInterval(() => {
    if (!ws.isAlive) {
      ws.terminate();
      wsClients.delete(key);
      ws.send(JSON.stringify({ type: 'logout', message: 'Session disconnected, please re-login' }));
      console.log(`Disconnected WebSocket client: ${key}`);
      return;
    }
    ws.isAlive = false;
    ws.ping();
  }, 30000); // Ping every 30 seconds
}

wss.on('connection', (ws, request, decoded) => {
  const key = decoded.role === 'admin' ? 'admin' : decoded.email;
  wsClients.set(key, ws);
  startHeartbeat(ws, key);

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  ws.on('close', () => {
    wsClients.delete(key);
    clearInterval(ws.pingInterval);
    ws.send(JSON.stringify({ type: 'logout', message: 'Session disconnected, please re-login' }));
    console.log(`WebSocket client closed: ${key}`);
  });
});

// NodeMailer Setup
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: { user: APP_EMAIL, pass: APP_PASSWORD }
});

const sendEmail = async (to, subject, text) => {
  try {
    await transporter.sendMail({ from: APP_EMAIL, to, subject, text });
    console.log(`Email sent: ${subject} to ${to}`);
  } catch (err) {
    console.error(`Failed to send email to ${to}:`, err.message);
  }
};

// Cron Jobs
cron.schedule('0 0 1 * *', async () => {
  const affiliates = await fetchAffiliates();
  for (const affiliate of affiliates) {
    affiliate.TotalSalesMonthly = 0;
    const affiliateIndex = affiliates.findIndex(a => a.Email === affiliate.Email);
    if (affiliateIndex !== -1) {
      await sheets.spreadsheets.values.update({
        spreadsheetId: AFFILIATES_SHEET_ID,
        range: `all affiliates!J${affiliateIndex + 2}`,
        valueInputOption: 'RAW',
        resource: { values: [[0]] }
      });
    }
  }

  leaderboardCache = {}; // ✅ Moved inside the function
  await updateCache();   // ✅ Valid now
  wsClients.forEach((ws, key) => {
    if (key !== 'admin') {
      ws.send(JSON.stringify({
        type: 'update',
        data: affiliates.find(a => a.Email === key)
      }));
    }
  });

  console.log('Monthly sales reset');
});

cron.schedule('0 0 30-31 * *', () => {
  (async () => {
    await sendEmail(
      APP_EMAIL,
      'Monthly Sales Reset Reminder',
      'Monthly sales will reset tomorrow at 00:00 UTC.'
    );
  })();
});


cron.schedule('0 0 * * *', async () => {
  const affiliates = await fetchAffiliates();
  for (const affiliate of affiliates) {
    const arrays = ['WithdrawalsJSON', 'RewardsJSON', 'NotificationsJSON'];
    for (const key of arrays) {
      let array = affiliate[key];
      if (array.length > 20) {
        array = array.sort((a, b) => new Date(a.date || a.timestamp) - new Date(b.date || b.timestamp)).slice(-20);
        affiliate[key] = array;
        console.log(`Trimmed ${key} for ${affiliate.Email}`);
      }
      if (JSON.stringify(array).length > 45000) {
        array = array.slice(-20);
        affiliate[key] = array;
        console.log(`Trimmed ${key} for ${affiliate.Email} due to size`);
      }
    }
    const affiliateIndex = affiliates.findIndex(a => a.Email === affiliate.Email);
if (affiliateIndex !== -1) {
  await sheets.spreadsheets.values.update({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `all affiliates!A${affiliateIndex + 2}:P`,
    valueInputOption: 'RAW',
    resource: { values: [Object.values(affiliate)] }
  });
}


  let response = await sheets.spreadsheets.values.get({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'sortedWithdrawals!A2:H'
  });
  let rows = response.data.values || [];
  if (rows.length > 40) {
    await sheets.spreadsheets.values.clear({
      spreadsheetId: ADMIN_SHEET_ID,
      range: `sortedWithdrawals!A2:H${rows.length + 1}`
    });
    await sheets.spreadsheets.values.update({
      spreadsheetId: ADMIN_SHEET_ID,
      range: `sortedWithdrawals!A2:H`,
      valueInputOption: 'RAW',
      resource: { values: rows.slice(-40) }
    });
    console.log(`Trimmed sortedWithdrawals to 40 rows`);
  }

  response = await sheets.spreadsheets.values.get({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'reset!A2:H'
  });
  rows = response.data.values || [];
  const now = new Date();
  rows = rows.filter(row => {
    const timestamp = new Date(row[5]);
    return (now - timestamp) / (1000 * 60 * 60) < 24;
  });
  await sheets.spreadsheets.values.clear({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'reset!A2:H'
  });
  if (rows.length) {
    await sheets.spreadsheets.values.update({
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'reset!A2:H',
      valueInputOption: 'RAW',
      resource: { values: rows }
    });
  }
  console.log(`Cleaned reset tab`);

  response = await sheets.spreadsheets.values.get({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'News!A2:C'
  });
  rows = response.data.values || [];
  if (rows.length > 40) {
    await sheets.spreadsheets.values.clear({
      spreadsheetId: ADMIN_SHEET_ID,
      range: `News!A2:C${rows.length + 1}`
    });
    await sheets.spreadsheets.values.update({
      spreadsheetId: ADMIN_SHEET_ID,
      range: `News!A2:C`,
      valueInputOption: 'RAW',
      resource: { values: rows.slice(-40) }
    });
    console.log(`Trimmed News to 40 rows`);
  }

  await updateCache();

// Sales Sync Cron Job
cron.schedule('0 * * * *', async () => {
  try {
    const response = await axios.get(`${BOT_STORE_API_URL}/api/sales`, {
      headers: { 'Authorization': `Bearer ${BOT_STORE_API_KEY}` }
    });
    if (!response.data.success || !Array.isArray(response.data.sales)) {
      console.error('Invalid sales data from bot store server');
      return;
    }
    const sales = response.data.sales;
    const affiliates = await fetchAffiliates();
    for (const sale of sales) {
      const { refCode, amount, item, timestamp } = sale;
      if (!refCode || amount <= 0) continue;
      const affiliate = affiliates.find(a => a.RefCode === refCode);
      if (!affiliate) {
        console.log(`No affiliate found for refCode: ${refCode}`);
        continue;
      }
      const commission = amount * cachedDataAffiliate.settings.commissionRate;
      affiliate.TotalSales += 1;
      affiliate.TotalSalesMonthly += 1;
      affiliate.CurrentBalance += commission;
      affiliate.NotificationsJSON.push({
        id: `NOTIF${Date.now()}`,
        read: false,
        colour: 'green',
        message: `Sale confirmed: ${amount} KES for ${item}, Commission: ${commission} KES`,
        timestamp: new Date().toISOString()
      });
      if (affiliate.NotificationsJSON.length > 20) {
        affiliate.NotificationsJSON = affiliate.NotificationsJSON.slice(-20);
      }
      const affiliateIndex = affiliates.findIndex(a => a.Email === affiliate.Email);
if (affiliateIndex !== -1) {
  await sheets.spreadsheets.values.update({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `all affiliates!I${affiliateIndex + 2}:O`,
    valueInputOption: 'RAW',
    resource: { values: [[
      affiliate.TotalSales,
      affiliate.TotalSalesMonthly,
      affiliate.CurrentBalance,
      affiliate.WithdrawnTotal,
      JSON.stringify(affiliate.WithdrawalsJSON),
      JSON.stringify(affiliate.RewardsJSON),
      JSON.stringify(affiliate.NotificationsJSON)
    ]] }
  });
}

      await logTransaction(affiliate.Email, 'sale_confirmed', { refCode, amount, commission, item });
      if (wsClients.has(affiliate.Email)) {
        wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'update', data: affiliate }));
        const wsClient = wsClients.get(affiliate.Email);
if (wsClient && wsClient.readyState === WebSocket.OPEN) {
  wsClient.send(JSON.stringify({ type: 'update', data: affiliate }));
  wsClient.send(JSON.stringify({
    type: 'notification',
    data: affiliate.NotificationsJSON[affiliate.NotificationsJSON.length - 1]
  }));
}

    }
    await updateCache();
    console.log('Sales sync completed');
  } catch (err) {
    console.error('Sales sync failed:', err.message);
  }
});

// Validation Functions
const validateEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const validateUsername = (username) => /^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d]{5,}$/.test(username);
const validateName = (name) => /^[a-zA-Z\s]+\s+[a-zA-Z\s]+$/.test(name);
const validatePassword = (password) => /^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d]{8,}$/.test(password);
const validateMpesaNumber = (number) => /^0[17]\d{8}$/.test(number);

// Authentication Middleware
const authenticateAffiliate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'affiliate') throw new Error('Invalid role');
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ success: false, message: 'Unauthorized' });
  }
};

const authenticateAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') throw new Error('Invalid role');
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ success: false, message: 'Unauthorized' });
  }
};

// Mark Notification as Read
app.post('/api/affiliate/mark-notification', authenticateAffiliate, async (req, res) => {
  try {
    const { notificationId } = req.body;
    if (!notificationId) return res.status(400).json({ success: false, message: 'Notification ID required' });
    const affiliate = cachedDataAffiliate.affiliates.find(a => a.Email === req.user.email);
    if (!affiliate) return res.status(404).json({ success: false, message: 'Affiliate not found' });

    const notifications = affiliate.NotificationsJSON || [];
    const notification = notifications.find(n => n.id === notificationId);
    if (!notification) return res.status(404).json({ success: false, message: 'Notification not found' });

    notification.read = true;

    const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.Email === affiliate.Email);
if (affiliateIndex !== -1) {
  await sheets.spreadsheets.values.update({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `all affiliates!O${affiliateIndex + 2}`,
    valueInputOption: 'RAW',
    resource: { values: [[JSON.stringify(notifications)]] },
  });
}


    await logTransaction(req.user.email, 'mark_notification', { notificationId });
    if (wsClients.has(affiliate.Email)) {
      wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'update', data: affiliate }));
    }
    res.json({ success: true, message: 'Notification marked as read' });
  } catch (error) {
    console.error('Error marking notification:', error.message);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Endpoints
app.post('/api/affiliate/register', registerLimiter, async (req, res) => {
  const { name, username, email, password, termsAccepted } = req.body;
  if (!validateName(name) || !validateUsername(username) || !validateEmail(email) || !validatePassword(password) || !termsAccepted) {
    return res.status(400).json({ success: false, message: 'Invalid input' });
  }
  const affiliates = await fetchAffiliates();
  if (affiliates.some(a => a.Email === email || a.Username === username)) {
    return res.status(400).json({ success: false, message: 'Email or username taken' });
  }
  if (affiliates.some(a => a.Email === email && ['blocked', 'deleted'].includes(a.Statusjson.status))) {
    return res.status(400).json({ success: false, message: 'Account blocked' });
  }
  const refCode = Math.random().toString(36).substring(2, 10).toUpperCase();
  const hashedPassword = await bcrypt.hash(password, 10);
  const affiliate = {
    Email: email,
    Username: username,
    Name: name,
    JoinDate: new Date().toISOString(),
    RefCode: refCode,
    Password: hashedPassword,
    Statusjson: JSON.stringify({ status: 'active' }),
    LinkClicks: 0,
    TotalSales: 0,
    TotalSalesMonthly: 0,
    CurrentBalance: 0,
    WithdrawnTotal: 0,
    WithdrawalsJSON: JSON.stringify([]),
    RewardsJSON: JSON.stringify([]),
    NotificationsJSON: JSON.stringify([]),
    MpesaDetails: JSON.stringify({})
  };
  await sheets.spreadsheets.values.append({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: 'all affiliates!A:P',
    valueInputOption: 'RAW',
    resource: { values: [Object.values(affiliate)] }
  });
  await logTransaction(email, 'register', { username, refCode });
  const token = jwt.sign({ email, username, role: 'affiliate' }, JWT_SECRET, { expiresIn: '7d' });
  await updateCache();
  res.json({ success: true, token, data: { name, username, refCode } });
});

app.post('/api/affiliate/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!validateEmail(email)) return res.status(401).json({ success: false, message: 'Invalid credentials' });
  const affiliates = await fetchAffiliates();
  const affiliate = affiliates.find(a => a.Email === email);
  if (!affiliate || !(await bcrypt.compare(password, affiliate.Password))) {
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
  if (affiliate.Statusjson.status === 'blocked') {
    return res.status(401).json({ success: false, message: 'Account suspended, please contact support' });
  }
  if (affiliate.Statusjson.status === 'deleted') {
    return res.status(401).json({ success: false, message: 'This email cannot create account' });
  }
  const token = jwt.sign({ email, username: affiliate.Username, role: 'affiliate' }, JWT_SECRET, { expiresIn: '7d' });
  if (wsClients.has(email)) {
    wsClients.get(email).send(JSON.stringify({ type: 'logout', message: 'Session disconnected, please re-login' }));
    wsClients.delete(email);
  }
  await logTransaction(email, 'login', {});
  res.json({ success: true, token, data: { name: affiliate.Name, username: affiliate.Username, refCode: affiliate.RefCode } });
});

app.post('/api/admin/affiliate/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  const settings = await fetchSettings();
  if (email !== settings.adminEmail || password !== settings.adminPassword) {
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
  const token = jwt.sign({ email, role: 'admin' }, JWT_SECRET, { expiresIn: '7d' });
  req.session.adminEmail = email;
  if (wsClients.has('admin')) {
    wsClients.get('admin').send(JSON.stringify({ type: 'logout', message: 'Session disconnected, please re-login' }));
    wsClients.delete('admin');
  }
  await logTransaction(email, 'admin_login', {});
  res.json({ success: true, token });
});

app.post('/api/affiliate/reset-password', resetLimiter, async (req, res) => {
  const { name, email, username, lastWithdrawalAmount, description } = req.body;
  if (!validateName(name) || !validateEmail(email) || !validateUsername(username) || description.length > 100) {
    return res.status(400).json({ success: false, message: 'Invalid input' });
  }
  const affiliates = await fetchAffiliates();
  if (!affiliates.some(a => a.Email === email && a.Username === username)) {
    return res.status(400).json({ success: false, message: 'Email or username does not exist' });
  }
  const resetEntry = [
    email, username, name, lastWithdrawalAmount || 0, description,
    new Date().toISOString(), 'Pending', ''
  ];
  await sheets.spreadsheets.values.append({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'reset!A:H',
    valueInputOption: 'RAW',
    resource: { values: [resetEntry] }
  });
  await logTransaction(email, 'reset_password_request', { username, lastWithdrawalAmount, description });
  console.log(`Password reset requested for ${email}`);
  res.json({ success: true, message: 'Reset request submitted' });
});

app.get('/api/affiliate/data', authenticateAffiliate, async (req, res) => {
  const affiliate = cachedDataAffiliate.affiliates.find(a => a.Email === req.user.email);
  if (!affiliate) return res.status(401).json({ success: false, message: 'Unauthorized' });

  // Update leaderboard with accurate momentum
  const leaderboard = cachedDataAffiliate.affiliates
    .sort((a, b) => b.TotalSalesMonthly - a.TotalSalesMonthly)
    .slice(0, 10)
    .map((a, i) => {
      const currentRank = i + 1;
      const prevRank = leaderboardCache[a.Email]?.rank;
      let momentum = 'same';
      if (!prevRank) {
        momentum = 'new';
      } else if (prevRank > currentRank) {
        momentum = 'up';
      } else if (prevRank < currentRank) {
        momentum = 'down';
      }
      return {
        email: a.Email,
        name: a.Name,
        totalSalesMonthly: a.TotalSalesMonthly,
        rank: currentRank,
        momentum
      };
    });
  leaderboardCache = Object.fromEntries(leaderboard.map(l => [l.email, { rank: l.rank }]));

  const newsResponse = await sheets.spreadsheets.values.get({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'News!A2:C'
  });
  const news = (newsResponse.data.values || []).map(row => ({ id: row[0], message: row[1], timestamp: row[2] }));
  res.json({
    success: true,
    data: {
      name: affiliate.Name,
      username: affiliate.Username,
      refCode: affiliate.RefCode,
      linkClicks: affiliate.LinkClicks,
      totalSales: affiliate.TotalSales,
      totalSalesMonthly: affiliate.TotalSalesMonthly,
      currentBalance: affiliate.CurrentBalance,
      withdrawnTotal: affiliate.WithdrawnTotal,
      withdrawalsJSON: affiliate.WithdrawalsJSON,
      rewardsJSON: affiliate.RewardsJSON,
      notificationsJSON: affiliate.NotificationsJSON,
      leaderboard,
      news,
      commissionRate: cachedDataAffiliate.settings.commissionRate,
      supportEmail: cachedDataAffiliate.settings.supportEmail,
      whatsappLink: cachedDataAffiliate.settings.whatsappLink,
      copyrightText: cachedDataAffiliate.settings.copyrightText,
      logoUrl: cachedDataAffiliate.settings.logoUrl
    }
  });
});

app.get('/api/admin/affiliate/affiliates', authenticateAdmin, async (req, res) => {
  res.json({
    success: true,
    affiliates: cachedDataAffiliate.affiliates.map(a => ({
      email: a.Email,
      username: a.Username,
      name: a.Name,
      joinDate: a.JoinDate,
      linkClicks: a.LinkClicks,
      totalSales: a.TotalSales,
      totalSalesMonthly: a.TotalSalesMonthly,
      currentBalance: a.CurrentBalance,
      withdrawnTotal: a.WithdrawnTotal,
      statusjson: a.Statusjson
    }))
  });
});

app.get('/api/admin/affiliate/withdrawals', authenticateAdmin, async (req, res) => {
  const response = await sheets.spreadsheets.values.get({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'pendingWithdrawals!A2:H'
  });
  const withdrawals = (response.data.values || []).map(row => ({
    email: row[0],
    name: row[1],
    timestamp: row[2],
    amount: parseFloat(row[3]),
    mpesaNumber: row[4],
    mpesaName: row[5],
    paymentRefcode: row[6],
    status: row[7]
  }));
  res.json({ success: true, withdrawals });
});

app.get('/api/admin/affiliate/sorted-withdrawals', authenticateAdmin, async (req, res) => {
  const response = await sheets.spreadsheets.values.get({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'sortedWithdrawals!A2:H'
  });
  const withdrawals = (response.data.values || []).slice(0, 40).map(row => ({
    email: row[0],
    name: row[1],
    timestamp: row[2],
    amount: parseFloat(row[3]),
    mpesaNumber: row[4],
    mpesaName: row[5],
    paymentRefcode: row[6],
    status: row[7]
  }));
  res.json({ success: true, withdrawals });
});

app.get('/api/admin/affiliate/staticpages', authenticateAdmin, async (req, res) => {
  res.json({ success: true, pages: cachedDataAffiliate.staticPages });
});

app.get('/api/admin/affiliate/reset-passwords', authenticateAdmin, async (req, res) => {
  const response = await sheets.spreadsheets.values.get({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'reset!A2:H'
  });
  const requests = (response.data.values || []).map(row => ({
    email: row[0],
    username: row[1],
    name: row[2],
    lastWithdrawalAmount: parseFloat(row[3] || '0'),
    description: row[4],
    timestamp: row[5],
    status: row[6],
    password: row[7]
  }));
  res.json({ success: true, requests });
});

app.post('/api/affiliate/track-click', async (req, res) => {
  const { refCode } = req.body;
  const affiliate = cachedDataAffiliate.affiliates.find(a => a.RefCode === refCode);
  if (!affiliate) return res.status(400).json({ success: false, message: 'Invalid refCode' });
  affiliate.LinkClicks += 1;
  const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.Email === affiliate.Email);
if (affiliateIndex !== -1) {
  await sheets.spreadsheets.values.update({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `all affiliates!H${affiliateIndex + 2}`,
    valueInputOption: 'RAW',
    resource: { values: [[affiliate.LinkClicks]] }
  });
}

  await logTransaction(affiliate.Email, 'track_click', { refCode });
  await updateCache();
  if (wsClients.has(affiliate.Email)) {
    wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'update', data: affiliate }));
  }
  res.json({ success: true });
});

app.post('/api/affiliate/confirmed-sale', async (req, res) => {
  const { refCode, amount, item, apiKey } = req.body;
  if (apiKey !== AFFILIATE_API_KEY) return res.status(401).json({ success: false, message: 'Invalid API key' });
  if (amount <= 0) return res.status(400).json({ success: false, message: 'Invalid amount' });
  const affiliate = cachedDataAffiliate.affiliates.find(a => a.RefCode === refCode);
  if (!affiliate) return res.status(400).json({ success: false, message: 'Invalid refCode' });
  const commission = amount * cachedDataAffiliate.settings.commissionRate;
  affiliate.TotalSales += 1;
  affiliate.TotalSalesMonthly += 1;
  affiliate.CurrentBalance += commission;
  affiliate.NotificationsJSON.push({
    id: `NOTIF${Date.now()}`,
    read: false,
    colour: 'green',
    message: `Sale confirmed: ${amount} KES, Commission: ${commission} KES`,
    timestamp: new Date().toISOString()
  });
  if (affiliate.NotificationsJSON.length > 20) {
    affiliate.NotificationsJSON = affiliate.NotificationsJSON.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp)).slice(-20);
  }
  const leaderboard = cachedDataAffiliate.affiliates
    .sort((a, b) => b.TotalSalesMonthly - a.TotalSalesMonthly)
    .slice(0, 10)
    .map((a, i) => ({ email: a.Email, rank: i + 1 }));
  const prevRank = leaderboardCache[affiliate.Email]?.rank;
  const newRank = leaderboard.find(l => l.email === affiliate.Email)?.rank;
  if (prevRank && newRank && prevRank !== newRank) {
    affiliate.NotificationsJSON.push({
      id: `NOTIF${Date.now()}`,
      read: false,
      colour: prevRank > newRank ? 'green' : 'red',
      message: `You moved ${prevRank > newRank ? 'up' : 'down'} in the leaderboard`,
      timestamp: new Date().toISOString()
    });
    if (affiliate.NotificationsJSON.length > 20) {
      affiliate.NotificationsJSON = affiliate.NotificationsJSON.slice(-20);
    }
  }
  leaderboardCache = Object.fromEntries(leaderboard.map(l => [l.email, { rank: l.rank }]));

const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.Email === affiliate.Email);
if (affiliateIndex !== -1) {
  await sheets.spreadsheets.values.update({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `all affiliates!I${affiliateIndex + 2}:O`,
    valueInputOption: 'RAW',
    resource: { values: [[
      affiliate.TotalSales,
      affiliate.TotalSalesMonthly,
      affiliate.CurrentBalance,
      affiliate.WithdrawnTotal,
      JSON.stringify(affiliate.WithdrawalsJSON),
      JSON.stringify(affiliate.RewardsJSON),
      JSON.stringify(affiliate.NotificationsJSON)
    ]] }
  });
}

  await logTransaction(affiliate.Email, 'confirmed_sale', { refCode, amount, commission, item });
  await updateCache();
  if (wsClients.has(affiliate.Email)) {
    wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'update', data: affiliate }));
    const wsClient = wsClients.get(affiliate.Email);
if (wsClient && wsClient.readyState === WebSocket.OPEN) {
  wsClient.send(JSON.stringify({ type: 'update', data: affiliate }));
  wsClient.send(JSON.stringify({
    type: 'notification',
    data: affiliate.NotificationsJSON[affiliate.NotificationsJSON.length - 1]
  }));
}

  res.json({ success: true });
});

app.post('/api/affiliate/sync-sales', authenticateAdmin, async (req, res) => {
  try {
    const response = await axios.get(`${BOT_STORE_API_URL}/api/sales`, {
      headers: { 'Authorization': `Bearer ${BOT_STORE_API_KEY}` }
    });
    if (!response.data.success || !Array.isArray(response.data.sales)) {
      return res.status(400).json({ success: false, message: 'Invalid sales data from bot store server' });
    }
    const sales = response.data.sales;
    const affiliates = await fetchAffiliates();
    let updatedAffiliates = [];
    for (const sale of sales) {
      const { refCode, amount, item, timestamp } = sale;
      if (!refCode || amount <= 0) {
        console.log(`Skipping invalid sale: refCode=${refCode}, amount=${amount}`);
        continue;
      }
      const affiliate = affiliates.find(a => a.RefCode === refCode);
      if (!affiliate) {
        console.log(`No affiliate found for refCode: ${refCode}`);
        continue;
      }
      const commission = amount * cachedDataAffiliate.settings.commissionRate;
      affiliate.TotalSales += 1;
      affiliate.TotalSalesMonthly += 1;
      affiliate.CurrentBalance += commission;
      affiliate.NotificationsJSON.push({
        id: `NOTIF${Date.now()}`,
        read: false,
        colour: 'green',
        message: `Sale confirmed: ${amount} KES for ${item}, Commission: ${commission} KES`,
        timestamp: new Date().toISOString()
      });
      if (affiliate.NotificationsJSON.length > 20) {
  affiliate.NotificationsJSON = affiliate.NotificationsJSON.slice(-20);
}

const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.Email === affiliate.Email);
if (affiliateIndex !== -1) {
  await sheets.spreadsheets.values.update({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `all affiliates!I${affiliateIndex + 2}:O`,
    valueInputOption: 'RAW',
    resource: { values: [[
      affiliate.TotalSales,
      affiliate.TotalSalesMonthly,
      affiliate.CurrentBalance,
      affiliate.WithdrawnTotal,
      JSON.stringify(affiliate.WithdrawalsJSON),
      JSON.stringify(affiliate.RewardsJSON),
      JSON.stringify(affiliate.NotificationsJSON)
    ]] }
  });
}

      await logTransaction(affiliate.Email, 'sync_sale', { refCode, amount, commission, item });
      updatedAffiliates.push(affiliate.Email);
      if (wsClients.has(affiliate.Email)) {
        wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'update', data: affiliate }));
        const wsClient = wsClients.get(affiliate.Email);
if (wsClient && wsClient.readyState === WebSocket.OPEN) {
  wsClient.send(JSON.stringify({ type: 'update', data: affiliate }));
  wsClient.send(JSON.stringify({
    type: 'notification',
    data: affiliate.NotificationsJSON[affiliate.NotificationsJSON.length - 1]
  }));
}

    }
    await updateCache();
    res.json({ success: true, updatedAffiliates });
  } catch (err) {
    console.error('Manual sales sync failed:', err.message);
    res.status(500).json({ success: false, message: 'Failed to sync sales: ' + err.message });
  }
});

app.post('/api/affiliate/request-withdrawal', authenticateAffiliate, async (req, res) => {
  const { amount, mpesaNumber, mpesaName, reuseDetails, password } = req.body;
  if (amount <= 0 || amount > cachedDataAffiliate.affiliates.find(a => a.Email === req.user.email).CurrentBalance || !validateMpesaNumber(mpesaNumber) || !validateName(mpesaName)) {
    return res.status(400).json({ success: false, message: 'Invalid input' });
  }
  const affiliate = cachedDataAffiliate.affiliates.find(a => a.Email === req.user.email);
  if (!(await bcrypt.compare(password, affiliate.Password))) {
    return res.status(401).json({ success: false, message: 'Incorrect password' });
  }
  affiliate.CurrentBalance -= amount;
  const withdrawal = {
    date: new Date().toISOString(),
    amount,
    mpesaNumber,
    mpesaName,
    status: 'Pending',
    mpesaRef: ''
  };
  affiliate.WithdrawalsJSON.push(withdrawal);
  if (affiliate.WithdrawalsJSON.length > 20) {
    affiliate.WithdrawalsJSON = affiliate.WithdrawalsJSON.sort((a, b) => new Date(a.date) - new Date(b.date)).slice(-20);
  }
  affiliate.NotificationsJSON.push({
    id: `NOTIF${Date.now()}`,
    read: false,
    colour: 'green',
    message: `Withdrawal of ${amount} KES submitted. You'll receive it soon as processed.`,
    timestamp: new Date().toISOString()
  });
  if (affiliate.NotificationsJSON.length > 20) {
    affiliate.NotificationsJSON = affiliate.NotificationsJSON.slice(-20);
  }
  if (reuseDetails) {
    affiliate.MpesaDetails = { mpesaNumber, mpesaName };
  }
  const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.Email === affiliate.Email);
  await sheets.spreadsheets.values.append({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'pendingWithdrawals!A:H',
    valueInputOption: 'RAW',
    resource: { values: [[
      affiliate.Email, affiliate.Name, withdrawal.date, amount,
      mpesaNumber, mpesaName, '', 'Pending'
    ]] }
  });
  await sheets.spreadsheets.values.update({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `all affiliates!K${affiliateIndex + 2}:P`,
    valueInputOption: 'RAW',
    resource: { values: [[
      affiliate.CurrentBalance,
      affiliate.WithdrawnTotal,
      JSON.stringify(affiliate.WithdrawalsJSON),
      JSON.stringify(affiliate.RewardsJSON),
      JSON.stringify(affiliate.NotificationsJSON),
      JSON.stringify(affiliate.MpesaDetails)
    ]] }
  });
  await sendEmail(
    APP_EMAIL,
    'New Withdrawal Request',
    `Affiliate: ${affiliate.Email}, Amount: ${amount} KES, MPESA: ${mpesaNumber}, Name: ${mpesaName}`
  );
  await logTransaction(affiliate.Email, 'request_withdrawal', { amount, mpesaNumber, mpesaName });
  await updateCache();
  if (wsClients.has(affiliate.Email)) {
    wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'update', data: affiliate }));
    const wsClient = wsClients.get(affiliate.Email);
if (wsClient && wsClient.readyState === WebSocket.OPEN) {
  wsClient.send(JSON.stringify({ type: 'update', data: affiliate }));
  wsClient.send(JSON.stringify({
    type: 'notification',
    data: affiliate.NotificationsJSON[affiliate.NotificationsJSON.length - 1]
  }));
}

  res.json({ success: true, withdrawal });
});

app.post('/api/admin/affiliate/withdrawals/:action', authenticateAdmin, async (req, res) => {
  const { email, withdrawalId, status, refCode } = req.body;
  if (!['Done', 'Dispute'].includes(status)) return res.status(400).json({ success: false, message: 'Invalid status' });
  if (status === 'Done' && !refCode) return res.status(400).json({ success: false, message: 'Enter the ref code' });
  const affiliate = cachedDataAffiliate.affiliates.find(a => a.Email === email);
  if (!affiliate) return res.status(400).json({ success: false, message: 'Affiliate not found' });
  const response = await sheets.spreadsheets.values.get({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'pendingWithdrawals!A2:H'
  });
  const withdrawals = (response.data.values || []).map((row, i) => ({ index: i + 2, row }));
  const withdrawal = withdrawals.find(w => w.row[0] === email && w.row[2] === withdrawalId);
  if (!withdrawal) return res.status(400).json({ success: false, message: 'Withdrawal not found' });
  const withdrawalData = {
    email: withdrawal.row[0],
    name: withdrawal.row[1],
    timestamp: withdrawal.row[2],
    amount: parseFloat(withdrawal.row[3]),
    mpesaNumber: withdrawal.row[4],
    mpesaName: withdrawal.row[5],
    paymentRefcode: status === 'Done' ? refCode : '',
    status
  };
  affiliate.WithdrawalsJSON = affiliate.WithdrawalsJSON.map(w =>
    w.date === withdrawalData.timestamp ? { ...w, status, mpesaRef: status === 'Done' ? refCode : '' } : w
  );
  if (status === 'Dispute') {
    affiliate.CurrentBalance += withdrawalData.amount;
  }
  affiliate.NotificationsJSON.push({
    id: `NOTIF${Date.now()}`,
    read: false,
    colour: status === 'Done' ? 'green' : 'red',
    message: status === 'Done' ? `Payment sent. M-PESA Ref: ${refCode}` : 'Payment failed. Contact support',
    timestamp: new Date().toISOString()
  });
  if (affiliate.NotificationsJSON.length > 20) {
    affiliate.NotificationsJSON = affiliate.NotificationsJSON.slice(-20);
  }
  await sheets.spreadsheets.values.append({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'sortedWithdrawals!A:H',
    valueInputOption: 'RAW',
    resource: { values: [Object.values(withdrawalData)] }
  });
  await sheets.spreadsheets.values.clear({
    spreadsheetId: ADMIN_SHEET_ID,
    range: `pendingWithdrawals!A${withdrawal.index}:H${withdrawal.index}`
  });
  const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.Email === affiliate.Email);
if (affiliateIndex !== -1) {
  await sheets.spreadsheets.values.update({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `all affiliates!K${affiliateIndex + 2}:O`,
    valueInputOption: 'RAW',
    resource: { values: [[
      affiliate.CurrentBalance,
      affiliate.WithdrawnTotal,
      JSON.stringify(affiliate.WithdrawalsJSON),
      JSON.stringify(affiliate.RewardsJSON),
      JSON.stringify(affiliate.NotificationsJSON)
    ]] }
  });
}

  await logTransaction(affiliate.Email, 'withdrawal_action', { status, refCode, amount: withdrawalData.amount });
  await updateCache();
  if (wsClients.has(affiliate.Email)) {
    wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'update', data: affiliate }));
    const wsClient = wsClients.get(affiliate.Email);
if (wsClient && wsClient.readyState === WebSocket.OPEN) {
  wsClient.send(JSON.stringify({ type: 'update', data: affiliate }));
  wsClient.send(JSON.stringify({
    type: 'notification',
    data: affiliate.NotificationsJSON[affiliate.NotificationsJSON.length - 1]
  }));
}

  res.json({ success: true });
});

app.post('/api/admin/affiliate/rewards', authenticateAdmin, async (req, res) => {
  const { type, percentage, amount, recipients } = req.body;
  if (type === 'percentage' && (percentage <= 0 || percentage > 1)) {
    return res.status(400).json({ success: false, message: 'Invalid percentage' });
  }
  if (type === 'spot' && (!amount || amount <= 0 || !recipients?.length)) {
    return res.status(400).json({ success: false, message: 'Invalid amount or recipients' });
  }
  const affiliates = cachedDataAffiliate.affiliates;
  if (type === 'percentage') {
    const topAffiliates = affiliates
      .sort((a, b) => b.TotalSalesMonthly - a.TotalSalesMonthly)
      .slice(0, 10);
    for (const affiliate of topAffiliates) {
      const reward = affiliate.TotalSalesMonthly * percentage;
      affiliate.CurrentBalance += reward;
      affiliate.RewardsJSON.push({
        date: new Date().toISOString(),
        type: 'leaderboard',
        amount: reward,
        description: `You were credited ${percentage * 100}% reward of your current sales this month`
      });
      if (affiliate.RewardsJSON.length > 20) {
        affiliate.RewardsJSON = affiliate.RewardsJSON.sort((a, b) => new Date(a.date) - new Date(b.date)).slice(-20);
      }
      affiliate.NotificationsJSON.push({
        id: `NOTIF${Date.now()}`,
        read: false,
        colour: 'blue',
        message: `Congratulations, you have been awarded ${reward} KES. Leaderboard awards`,
        timestamp: new Date().toISOString()
      });
      if (affiliate.NotificationsJSON.length > 20) {
        affiliate.NotificationsJSON = affiliate.NotificationsJSON.slice(-20);
      }
      const affiliateIndex = affiliates.findIndex(a => a.Email === affiliate.Email);
if (affiliateIndex !== -1) {
  await sheets.spreadsheets.values.update({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `all affiliates!K${affiliateIndex + 2}:O`,
    valueInputOption: 'RAW',
    resource: { values: [[
      affiliate.CurrentBalance,
      affiliate.WithdrawnTotal,
      JSON.stringify(affiliate.WithdrawalsJSON),
      JSON.stringify(affiliate.RewardsJSON),
      JSON.stringify(affiliate.NotificationsJSON)
    ]] }
  });
}

      await logTransaction(affiliate.Email, 'reward_percentage', { reward, percentage });
      if (wsClients.has(affiliate.Email)) {
        wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'update', data: affiliate }));
        const wsClient = wsClients.get(affiliate.Email);
if (wsClient && wsClient.readyState === WebSocket.OPEN) {
  wsClient.send(JSON.stringify({ type: 'update', data: affiliate }));
  wsClient.send(JSON.stringify({
    type: 'notification',
    data: affiliate.NotificationsJSON[affiliate.NotificationsJSON.length - 1]
  }));
}

    }
  } else {
    for (const email of recipients) {
      const affiliate = affiliates.find(a => a.Email === email);
      if (!affiliate) continue;
      affiliate.CurrentBalance += amount;
      affiliate.RewardsJSON.push({
        date: new Date().toISOString(),
        type: 'spot',
        amount,
        description: `Spot reward of ${amount} KES`
      });
      if (affiliate.RewardsJSON.length > 20) {
        affiliate.RewardsJSON = affiliate.RewardsJSON.sort((a, b) => new Date(a.date) - new Date(b.date)).slice(-20);
      }
      affiliate.NotificationsJSON.push({
        id: `NOTIF${Date.now()}`,
        read: false,
        colour: 'blue',
        message: `Congratulations, you have been awarded ${amount} KES`,
        timestamp: new Date().toISOString()
      });
      if (affiliate.NotificationsJSON.length > 20) {
        affiliate.NotificationsJSON = affiliate.NotificationsJSON.slice(-20);
      }
      const affiliateIndex = affiliates.findIndex(a => a.Email === affiliate.Email);
if (affiliateIndex !== -1) {
  await sheets.spreadsheets.values.update({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `all affiliates!K${affiliateIndex + 2}:O`,
    valueInputOption: 'RAW',
    resource: { values: [[
      affiliate.CurrentBalance,
      affiliate.WithdrawnTotal,
      JSON.stringify(affiliate.WithdrawalsJSON),
      JSON.stringify(affiliate.RewardsJSON),
      JSON.stringify(affiliate.NotificationsJSON)
    ]] }
  });
}

      await logTransaction(affiliate.Email, 'reward_spot', { amount });
      if (wsClients.has(affiliate.Email)) {
        wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'update', data: affiliate }));
        const wsClient = wsClients.get(affiliate.Email);
if (wsClient && wsClient.readyState === WebSocket.OPEN) {
  wsClient.send(JSON.stringify({ type: 'update', data: affiliate }));
  wsClient.send(JSON.stringify({
    type: 'notification',
    data: affiliate.NotificationsJSON[affiliate.NotificationsJSON.length - 1]
  }));
}

    }
    await sheets.spreadsheets.values.append({
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'News!A:C',
      valueInputOption: 'RAW',
      resource: { values: [[
        `NEWS${Date.now()}`,
        'Rewards have been issued for the leaderboard and some spot clients',
        new Date().toISOString()
      ]] }
    });
  }
  await updateCache();
  res.json({ success: true });
});

app.post('/api/admin/affiliate/staticpages', authenticateAdmin, async (req, res) => {
  const { slug, title, content } = req.body;
  if (!slug.match(/^\/affiliate-[a-z-]+$/)) return res.status(400).json({ success: false, message: 'Invalid slug' });
  if (!title || !content) return res.status(400).json({ success: false, message: 'Invalid input' });
  const sanitizedContent = sanitizeHtml(content);
  const pages = cachedDataAffiliate.staticPages;
  const pageIndex = pages.findIndex(p => p.Slug === slug);
  if (pageIndex >= 0) {
    pages[pageIndex] = { Slug: slug, Title: title, Content: sanitizedContent };
    await sheets.spreadsheets.values.update({
      spreadsheetId: ADMIN_SHEET_ID,
      range: `staticPagesAffiliate!A${pageIndex + 2}:C`,
      valueInputOption: 'RAW',
      resource: { values: [[slug, title, sanitizedContent]] }
    });
  } else {
    await sheets.spreadsheets.values.append({
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'staticPagesAffiliate!A:C',
      valueInputOption: 'RAW',
      resource: { values: [[slug, title, sanitizedContent]] }
    });
  }
  await logTransaction(req.user.email, 'update_static_page', { slug, title });
  await updateCache();
  res.json({ success: true });
});

app.post('/api/admin/affiliate/staticpages/delete', authenticateAdmin, async (req, res) => {
  const { slug } = req.body;
  const pages = cachedDataAffiliate.staticPages;
  const pageIndex = pages.findIndex(p => p.Slug === slug);
  if (pageIndex < 0) return res.status(404).json({ success: false, message: 'Page not found' });
  await sheets.spreadsheets.values.clear({
    spreadsheetId: ADMIN_SHEET_ID,
    range: `staticPagesAffiliate!A${pageIndex + 2}:C${pageIndex + 2}`
  });
  await logTransaction(req.user.email, 'delete_static_page', { slug });
  await updateCache();
  res.json({ success: true });
});

app.get('/api/affiliate/static-page/:slug', async (req, res) => {
  const { slug } = req.params;
  const page = cachedDataAffiliate.staticPages.find(p => p.Slug === `/affiliate-${slug}`);
  if (!page) return res.status(404).json({ success: false, message: 'Page not found' });
  res.json({ success: true, page });
});

app.post('/api/admin/affiliate/communication', authenticateAdmin, async (req, res) => {
  const { type, message, enabled, filter } = req.body;
  if (!message || !['urgent', 'news'].includes(type)) return res.status(400).json({ success: false, message: 'Invalid input' });
  if (type === 'urgent') {
    cachedDataAffiliate.settings.urgentPopup = { message, enabled };
    await sheets.spreadsheets.values.update({
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'settingsAffiliate!A8:B8',
      valueInputOption: 'RAW',
      resource: { values: [['urgentPopup', JSON.stringify({ message, enabled })]] }
    });
    if (enabled) {
      const notification = {
        id: `NOTIF${Date.now()}`,
        read: false,
        colour: 'red',
        message,
        timestamp: new Date().toISOString()
      };
      for (const affiliate of cachedDataAffiliate.affiliates) {
        affiliate.NotificationsJSON.push(notification);
        if (affiliate.NotificationsJSON.length > 20) {
          affiliate.NotificationsJSON = affiliate.NotificationsJSON.slice(-20);
        }
        const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.Email === affiliate.Email);
if (affiliateIndex !== -1) {
  await sheets.spreadsheets.values.update({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `all affiliates!O${affiliateIndex + 2}`,
    valueInputOption: 'RAW',
    resource: { values: [[JSON.stringify(affiliate.NotificationsJSON)]] }
  });
}

await logTransaction(affiliate.Email, 'urgent_notification', { message });

const wsClient = wsClients.get(affiliate.Email);
if (wsClient && wsClient.readyState === WebSocket.OPEN) {
  wsClient.send(JSON.stringify({ type: 'notification', data: notification }));
}

      }
    }
  } else {
    const news = {
      id: `NEWS${Date.now()}`,
      message,
      timestamp: new Date().toISOString()
    };
    await sheets.spreadsheets.values.append({
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'News!A:C',
      valueInputOption: 'RAW',
      resource: { values: [[news.id, news.message, news.timestamp]] }
    });
    let targetAffiliates = cachedDataAffiliate.affiliates;
    if (filter === 'active') {
      targetAffiliates = targetAffiliates.filter(a => a.Statusjson.status === 'active');
    } else if (filter === 'top') {
      targetAffiliates = targetAffiliates.sort((a, b) => b.TotalSalesMonthly - a.TotalSalesMonthly).slice(0, 10);
    }
    targetAffiliates.forEach(affiliate => {
      if (wsClients.has(affiliate.Email)) {
        wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'news', data: news }));
      }
    });
    await logTransaction(req.user.email, 'news_communication', { message, filter });
  }
  await updateCache();
  res.json({ success: true });
});

app.post('/api/admin/affiliate/settings', authenticateAdmin, async (req, res) => {
  const { supportEmail, copyrightText, whatsappLink, commissionRate, logoUrl, adminEmail, adminPassword } = req.body;
  if (!validateEmail(supportEmail) || !validateEmail(adminEmail) || commissionRate < 0 || commissionRate > 1 || !copyrightText || !whatsappLink || !adminPassword) {
    return res.status(400).json({ success: false, message: 'Invalid input' });
  }
  if (logoUrl && !/^https?:\/\/[^\s/$.?#].[^\s]*$/.test(logoUrl)) {
    return res.status(400).json({ success: false, message: 'Invalid logo URL' });
  }
  const settings = {
    supportEmail, copyrightText, whatsappLink, commissionRate: JSON.stringify(commissionRate),
    logoUrl, adminEmail, adminPassword, urgentPopup: cachedDataAffiliate.settings.urgentPopup
  };
  await sheets.spreadsheets.values.update({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'settingsAffiliate!A2:B',
    valueInputOption: 'RAW',
    resource: { values: Object.entries(settings) }
  });
  await logTransaction(req.user.email, 'update_settings', { supportEmail, commissionRate });
  await updateCache();
  cachedDataAffiliate.affiliates.forEach(affiliate => {
    if (wsClients.has(affiliate.Email)) {
      wsClients.get(affiliate.Email).send(JSON.stringify({
        type: 'settings',
        data: { commissionRate, supportEmail, whatsappLink, copyrightText, logoUrl }
      }));
    }
  });
  res.json({ success: true });
});

app.post('/api/affiliate/update-password', authenticateAffiliate, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!validatePassword(newPassword)) return res.status(400).json({ success: false, message: 'Invalid new password' });
  const affiliate = cachedDataAffiliate.affiliates.find(a => a.Email === req.user.email);
  if (!(await bcrypt.compare(currentPassword, affiliate.Password))) {
    return res.status(401).json({ success: false, message: 'Incorrect current password' });
  }
  affiliate.Password = await bcrypt.hash(newPassword, 10);

const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.Email === affiliate.Email);
if (affiliateIndex !== -1) {
  await sheets.spreadsheets.values.update({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `all affiliates!F${affiliateIndex + 2}`,
    valueInputOption: 'RAW',
    resource: { values: [[affiliate.Password]] }
  });
}

  await logTransaction(affiliate.Email, 'update_password', {});
  if (wsClients.has(affiliate.Email)) {
    wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'logout', message: 'Session disconnected, please re-login' }));
    wsClients.delete(affiliate.Email);
  }
  await updateCache();
  res.json({ success: true });
});

app.post('/api/affiliate/delete-account', authenticateAffiliate, async (req, res) => {
  const affiliate = cachedDataAffiliate.affiliates.find(a => a.Email === req.user.email);
  if (affiliate.CurrentBalance >= 1 || affiliate.WithdrawalsJSON.some(w => w.status === 'Pending')) {
    return res.status(400).json({ success: false, message: 'Withdraw all money before deleting account' });
  }
  affiliate.Statusjson = { status: 'deleted' };
  affiliate.NotificationsJSON.push({
    id: `NOTIF${Date.now()}`,
    read: false,
    colour: 'red',
    message: 'Account deleted',
    timestamp: new Date().toISOString()
  });
  if (affiliate.NotificationsJSON.length > 20) {
    affiliate.NotificationsJSON = affiliate.NotificationsJSON.slice(-20);
  }
  const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.Email === affiliate.Email);
if (affiliateIndex !== -1) {
  await sheets.spreadsheets.values.update({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `all affiliates!G${affiliateIndex + 2}:O`,
    valueInputOption: 'RAW',
    resource: { values: [[
      JSON.stringify(affiliate.Statusjson),
      affiliate.LinkClicks,
      affiliate.TotalSales,
      affiliate.TotalSalesMonthly,
      affiliate.CurrentBalance,
      affiliate.WithdrawnTotal,
      JSON.stringify(affiliate.WithdrawalsJSON),
      JSON.stringify(affiliate.RewardsJSON),
      JSON.stringify(affiliate.NotificationsJSON)
    ]] }
  });
}

  await logTransaction(affiliate.Email, 'delete_account', {});
  if (wsClients.has(affiliate.Email)) {
    wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'logout', message: 'Session disconnected, please re-login' }));
    wsClients.delete(affiliate.Email);
  }
  await updateCache();
  res.json({ success: true });
});

app.post('/api/admin/affiliate/reset-password', authenticateAdmin, async (req, res) => {
  const { email, status, password } = req.body;
  if (!['approved', 'declined'].includes(status)) return res.status(400).json({ success: false, message: 'Invalid status' });
  const response = await sheets.spreadsheets.values.get({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'reset!A2:H'
  });
  const resets = (response.data.values || []).map((row, i) => ({ index: i + 2, row }));
const resetEntry = resets.find(r => r.row[0] === email);
if (!resetEntry) return res.status(400).json({ success: false, message: 'Reset request not found' });

if (status === 'approved') {
  if (!password || password.length < 12) return res.status(400).json({ success: false, message: 'Invalid password' });

  const affiliate = cachedDataAffiliate.affiliates.find(a => a.Email === email);
  if (!affiliate) return res.status(404).json({ success: false, message: 'Affiliate not found' });

  affiliate.Password = await bcrypt.hash(password, 10);
  const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.Email === email);

  if (affiliateIndex !== -1) {
    await sheets.spreadsheets.values.update({
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `all affiliates!F${affiliateIndex + 2}`,
      valueInputOption: 'RAW',
      resource: { values: [[affiliate.Password]] }
    });
  }

    await sheets.spreadsheets.values.update({
      spreadsheetId: ADMIN_SHEET_ID,
      range: `reset!G${resetEntry.index}:H${resetEntry.index}`,
      valueInputOption: 'RAW',
      resource: { values: [['Approved', password]] }
    });
    await logTransaction(email, 'reset_password_approved', {});
    console.log(`Password reset approved for ${email}`);
  } else {
    await sheets.spreadsheets.values.clear({
      spreadsheetId: ADMIN_SHEET_ID,
      range: `reset!A${resetEntry.index}:H${resetEntry.index}`
    });
    await logTransaction(email, 'reset_password_declined', {});
    console.log(`Password reset declined for ${email}`);
  }
  await updateCache();
  res.json({ success: true });
});

// Default Route to Serve affiliate.html
app.get('/', (req, res) => {
  const filePath = path.join(publicPath, 'affiliate.html');
  console.log(`Serving default route: ${filePath}`);
  res.sendFile(filePath, (err) => {
    if (err) {
      console.error(`Error serving affiliate.html: ${err.message}`);
      res.status(404).json({ success: false, message: 'File not found' });
    }
  });
});

// WebSocket Server
const server = app.listen(port, () => {
  (async () => {
    await initializeSheets();
    await updateCache();
    cron.schedule('*/15 * * * *', updateCache);
    console.log(`Server running on port ${port}`);
    fs.readdir(publicPath, (err, files) => {
      if (err) {
        console.error(`Error reading public directory: ${err.message}`);
      } else {
        console.log(`Static files available in ${publicPath}:`, files);
      }
    });
  })();
});

server.on('upgrade', (request, socket, head) => {
  const url = new URL(request.url, `http://${request.headers.host}`);
  const token = url.searchParams.get('token');
  const decoded = validateWebSocket(token);
  if (!decoded) {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(request, socket, head, ws => {
    wss.emit('connection', ws, request, decoded);
  });
});
