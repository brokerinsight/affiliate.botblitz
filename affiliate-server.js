const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { google } = require('googleapis');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');
const cron = require('node-cron');
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
      throw new Error('GOOGLE_CREDENTIALS missing required fields');
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
app.use(express.static('public'));

// Rate Limiting
const globalPostLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 100,
  message: 'Too many requests, please try again later'
});
app.use('/api', globalPostLimiter);

const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.body.email || 'unknown',
  message: 'Too many login attempts, please try again later'
});
const registerLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.body.email || 'unknown',
  message: 'Too many registration attempts, please try again later'
});
const resetLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.body.email || 'unknown',
  message: 'Too many reset attempts, please try again later'
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
          requests: [{ addSheet: { properties: { title: tabName } } }]
        }
      });
      console.log(`Created tab '${tabName}' in spreadsheet ${spreadsheetId}`);
    };

    const affiliatesHeaders = [
      'Email', 'Username', 'Name', 'JoinDate', 'RefCode', 'Password',
      'Statusjson', 'LinkClicks', 'TotalSales', 'TotalSalesMonthly',
      'CurrentBalance', 'WithdrawnTotal', 'WithdrawalsJSON', 'RewardsJSON',
      'NotificationsJSON', 'ResetJSON', 'LeaderboardJSON', 'MpesaDetails'
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
      range: 'all affiliates!A1:R1',
      valueInputOption: 'RAW',
      resource: { values: [affiliatesHeaders] }
    });

    const settingsData = [
      ['supportEmail', 'derivbotstore@gmail.com'],
      ['copyrightText', 'Deriv Bot Store Affiliates 2025'],
      ['whatsappLink', 'https://wa.link/4wppln'],
      ['commissionRate', '0.2'],
      ['logoUrl', ''],
      ['adminEmail', 'martinke444@gmail.com'],
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

    const adminTabsConfig = [
      { name: 'staticPagesAffiliate', headers: ['Slug', 'Title', 'Content'] },
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
    }
  } catch (err) {
    console.error('Failed to initialize sheets:', err.message);
    process.exit(1);
  }
};

// Cache
let cachedDataAffiliate = {
  affiliates: [],
  settings: {},
  staticPages: [],
  news: []
};

// Transaction Logging
async function logTransaction(email, action, details) {
  try {
    await sheets.spreadsheets.values.append({
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: 'transactionLog!A:C',
      valueInputOption: 'RAW',
      resource: { values: [[new Date().toISOString(), email, `${action}: ${JSON.stringify(details)}`]] }
    });
  } catch (error) {
    console.error('Error logging transaction:', error.message);
  }
}

// Fetch and Cache Data
const fetchAffiliates = async () => {
  const response = await sheets.spreadsheets.values.get({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: 'all affiliates!A2:R'
  });
  const rows = response.data.values || [];
  return rows.map(row => ({
    Email: row[0] || '',
    Username: row[1] || '',
    Name: row[2] || '',
    JoinDate: row[3] || '',
    RefCode: row[4] || '',
    Password: row[5] || '',
    Statusjson: JSON.parse(row[6] || '{"status": "active"}'),
    LinkClicks: parseInt(row[7] || '0'),
    TotalSales: parseInt(row[8] || '0'),
    TotalSalesMonthly: parseInt(row[9] || '0'),
    CurrentBalance: parseFloat(row[10] || '0'),
    WithdrawnTotal: parseFloat(row[11] || '0'),
    WithdrawalsJSON: parseAndSort(row[12], 'date'),
RewardsJSON: parseAndSort(row[13], 'date'),
NotificationsJSON: parseAndSort(row[14], 'timestamp'),
ResetJSON: parseAndSort(row[15], 'timestamp'),
LeaderboardJSON: JSON.parse(row[16] || '{"previousRank": 0, "currentRank": 0}'),
MpesaDetails: JSON.parse(row[17] || '{}')
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

const fetchNews = async () => {
  const response = await sheets.spreadsheets.values.get({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'News!A2:C'
  });
  const rows = response.data.values || [];
  return rows.map(row => ({ Id: row[0], Message: row[1], Timestamp: row[2] }))
    .sort((a, b) => new Date(b.Timestamp) - new Date(a.Timestamp));
};

const updateAffiliateField = async (email, field, value) => {
  const affiliates = await fetchAffiliates();
  const affiliateIndex = affiliates.findIndex(a => a.Email === email);
  if (affiliateIndex === -1) throw new Error('Affiliate not found');
  const rowIndex = affiliateIndex + 2;
  const columnMap = {
    CurrentBalance: 'K',
    WithdrawalsJSON: 'M',
    RewardsJSON: 'N',
    NotificationsJSON: 'O',
    ResetJSON: 'P',
    LeaderboardJSON: 'Q',
    MpesaDetails: 'R',
    Statusjson: 'G',
    Password: 'F',
    TotalSales: 'I',
    TotalSalesMonthly: 'J',
    WithdrawnTotal: 'L'
  };
  if (!columnMap[field]) throw new Error('Unsupported field');
  await sheets.spreadsheets.values.update({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `all affiliates!${columnMap[field]}${rowIndex}`,
    valueInputOption: 'RAW',
    resource: { values: [[typeof value === 'object' ? JSON.stringify(value) : value]] }
  });
  await updateCache();
};

const updateAffiliateByEmail = async (email, updatedData) => {
  const affiliates = await fetchAffiliates();
  const affiliateIndex = affiliates.findIndex(a => a.Email === email);
  if (affiliateIndex === -1) throw new Error('Affiliate not found');
  const rowIndex = affiliateIndex + 2;
  await sheets.spreadsheets.values.update({
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `all affiliates!A${rowIndex}:R${rowIndex}`,
    valueInputOption: 'RAW',
    resource: {
      values: [[
        updatedData.Email, updatedData.Username, updatedData.Name, updatedData.JoinDate,
        updatedData.RefCode, updatedData.Password, JSON.stringify(updatedData.Statusjson),
        updatedData.LinkClicks, updatedData.TotalSales, updatedData.TotalSalesMonthly,
        updatedData.CurrentBalance, updatedData.WithdrawnTotal,
        JSON.stringify(updatedData.WithdrawalsJSON), JSON.stringify(updatedData.RewardsJSON),
        JSON.stringify(updatedData.NotificationsJSON), JSON.stringify(updatedData.ResetJSON),
        JSON.stringify(updatedData.LeaderboardJSON), JSON.stringify(updatedData.MpesaDetails)
      ]]
    }
  });
  await updateCache();
};

const updateCache = async () => {
  cachedDataAffiliate.affiliates = await fetchAffiliates();
  cachedDataAffiliate.settings = await fetchSettings();
  cachedDataAffiliate.staticPages = await fetchStaticPages();
  cachedDataAffiliate.news = await fetchNews();
};

// WebSocket Setup
const wss = new WebSocket.Server({ noServer: true });
const wsClients = new Map();

const validateWebSocket = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
};

function startHeartbeat(ws, key) {
  ws.isAlive = true;
  ws.pingInterval = setInterval(() => {
    if (!ws.isAlive) {
      ws.terminate();
      wsClients.delete(key);
      console.log(`Disconnected WebSocket client: ${key}`);
      return;
    }
    ws.isAlive = false;
    ws.ping();
  }, 30000);
}

wss.on('connection', (ws, request, decoded) => {
  const key = decoded.role === 'admin' ? 'admin' : decoded.email;
  wsClients.set(key, ws);
  startHeartbeat(ws, key);
  logTransaction(key, 'websocket_connect', { role: decoded.role });

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      if (data.type === 'username_check' && decoded.role === 'affiliate') {
        const affiliates = await fetchAffiliates();
        const available = !affiliates.some(a => a.Username === data.username);
        ws.send(JSON.stringify({
          type: 'username_check',
          data: { available, message: available ? 'Username available' : 'Username taken' }
        }));
      }
    } catch (err) {
      console.error('WebSocket message error:', err.message);
    }
  });

  ws.on('close', () => {
    wsClients.delete(key);
    clearInterval(ws.pingInterval);
    console.log(`WebSocket client closed: ${key}`);
    logTransaction(key, 'websocket_disconnect', { role: decoded.role });
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
  } catch (err) {
    console.error(`Failed to send email to ${to}:`, err.message);
  }
};

// Cron Jobs
cron.schedule('0 0 1 * *', async () => {
  const affiliates = await fetchAffiliates();
  for (const affiliate of affiliates) {
    affiliate.TotalSalesMonthly = 0;
    affiliate.LeaderboardJSON.previousRank = affiliate.LeaderboardJSON.currentRank;
    affiliate.LeaderboardJSON.currentRank = 0;
    await updateAffiliateByEmail(affiliate.Email, affiliate);
  }
  const updatedAffiliates = await fetchAffiliates();
  const rankedAffiliates = updatedAffiliates
    .filter(a => a.Statusjson.status === 'active')
    .sort((a, b) => b.TotalSalesMonthly - a.TotalSalesMonthly);
  for (let i = 0; i < Math.min(rankedAffiliates.length, 10); i++) {
    const affiliate = rankedAffiliates[i];
    affiliate.LeaderboardJSON.currentRank = i + 1;
    if (affiliate.LeaderboardJSON.previousRank && affiliate.LeaderboardJSON.currentRank !== affiliate.LeaderboardJSON.previousRank) {
      const message = affiliate.LeaderboardJSON.currentRank < affiliate.LeaderboardJSON.previousRank
        ? 'You moved up in the leaderboard!'
        : 'You moved down in the leaderboard.';
      affiliate.NotificationsJSON.unshift({
        id: `NOTIF${Date.now()}`,
        read: false,
        colour: affiliate.LeaderboardJSON.currentRank < affiliate.LeaderboardJSON.previousRank ? 'green' : 'red',
        message,
        timestamp: new Date().toISOString()
      });
      if (wsClients.has(affiliate.Email)) {
        wsClients.get(affiliate.Email).send(JSON.stringify({
          type: 'notification',
          data: affiliate.NotificationsJSON[0]
        }));
      }
      await updateAffiliateField(affiliate.Email, 'NotificationsJSON', affiliate.NotificationsJSON);
    }
    await updateAffiliateField(affiliate.Email, 'LeaderboardJSON', affiliate.LeaderboardJSON);
  }
  await updateCache();
  wsClients.forEach((ws, key) => {
    if (key !== 'admin') {
      ws.send(JSON.stringify({ type: 'update', data: updatedAffiliates.find(a => a.Email === key) }));
    }
  });
});

cron.schedule('0 0 30-31 * *', () => {
  sendEmail(
    APP_EMAIL,
    'Monthly Sales Reset Reminder',
    'Monthly sales will reset tomorrow at 00:00 UTC.'
  );
});

cron.schedule('0 0 * * *', async () => {
  const affiliates = await fetchAffiliates();
  for (const affiliate of affiliates) {
    const arrays = ['WithdrawalsJSON', 'RewardsJSON', 'NotificationsJSON', 'ResetJSON'];
    for (const key of arrays) {
      affiliate[key] = affiliate[key]
        .sort((a, b) => new Date(b.date || b.timestamp) - new Date(a.date || a.timestamp))
        .slice(0, 20);
      await updateAffiliateField(affiliate.Email, key, affiliate[key]);
    }
  }
  let response = await sheets.spreadsheets.values.get({
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'News!A2:C'
  });
  let rows = response.data.values || [];
  if (rows.length > 40) {
    rows = rows.sort((a, b) => new Date(b[2]) - new Date(a[2])).slice(0, 40);
    await sheets.spreadsheets.values.clear({
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'News!A2:C'
    });
    await sheets.spreadsheets.values.update({
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'News!A2:C',
      valueInputOption: 'RAW',
      resource: { values: rows }
    });
  }
  await updateCache();
});

cron.schedule('*/15 * * * *', updateCache);

cron.schedule('*/10 * * * *', async () => {
  try {
    const response = await axios.get(`${BOT_STORE_API_URL}/api/sales`, {
      headers: { 'Authorization': `Bearer ${BOT_STORE_API_KEY}` }
    });
    if (!response.data.success || !Array.isArray(response.data.sales)) return;
    const sales = response.data.sales;
    const affiliates = await fetchAffiliates();
    for (const sale of sales) {
      const { refCode, amount, item } = sale;
      if (!refCode || amount <= 0) continue;
      const affiliate = affiliates.find(a => a.RefCode === refCode);
      if (!affiliate) continue;
      const commission = amount * cachedDataAffiliate.settings.commissionRate;
      affiliate.TotalSales += 1;
      affiliate.TotalSalesMonthly += 1;
      affiliate.CurrentBalance += commission;
      affiliate.NotificationsJSON.unshift({
        id: `NOTIF${Date.now()}`,
        read: false,
        colour: 'green',
        message: `Sale confirmed: ${amount} KES for ${item}, Commission: ${commission} KES`,
        timestamp: new Date().toISOString()
      });
      if (affiliate.NotificationsJSON.length > 20) {
        affiliate.NotificationsJSON = affiliate.NotificationsJSON.slice(0, 20);
      }
      affiliate.LeaderboardJSON.previousRank = affiliate.LeaderboardJSON.currentRank;
      const rankedAffiliates = affiliates
        .filter(a => a.Statusjson.status === 'active')
        .sort((a, b) => b.TotalSalesMonthly - a.TotalSalesMonthly);
      affiliate.LeaderboardJSON.currentRank = rankedAffiliates.findIndex(a => a.Email === affiliate.Email) + 1;
      if (affiliate.LeaderboardJSON.previousRank && affiliate.LeaderboardJSON.currentRank !== affiliate.LeaderboardJSON.previousRank) {
        affiliate.NotificationsJSON.unshift({
          id: `NOTIF${Date.now()}`,
          read: false,
          colour: affiliate.LeaderboardJSON.currentRank < affiliate.LeaderboardJSON.previousRank ? 'green' : 'red',
          message: affiliate.LeaderboardJSON.currentRank < affiliate.LeaderboardJSON.previousRank
            ? 'You moved up in the leaderboard!'
            : 'You moved down in the leaderboard.',
          timestamp: new Date().toISOString()
        });
      }
      await updateAffiliateField(affiliate.Email, 'TotalSales', affiliate.TotalSales);
      await updateAffiliateField(affiliate.Email, 'TotalSalesMonthly', affiliate.TotalSalesMonthly);
      await updateAffiliateField(affiliate.Email, 'CurrentBalance', affiliate.CurrentBalance);
      await updateAffiliateField(affiliate.Email, 'NotificationsJSON', affiliate.NotificationsJSON);
      await updateAffiliateField(affiliate.Email, 'LeaderboardJSON', affiliate.LeaderboardJSON);
      await logTransaction(affiliate.Email, 'sale_confirmed', { refCode, amount, commission, item });
      if (wsClients.has(affiliate.Email)) {
        wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'update', data: affiliate }));
        wsClients.get(affiliate.Email).send(JSON.stringify({
          type: 'notification',
          data: affiliate.NotificationsJSON[0]
        }));
      }
    }
    await updateCache();
  } catch (err) {
    console.error('Sales sync failed:', err.message);
  }
});
function parseAndSort(jsonStr, sortKey = 'date') {
  try {
    const data = JSON.parse(jsonStr || '[]');
    return Array.isArray(data)
      ? data.sort((a, b) => new Date(b[sortKey]) - new Date(a[sortKey]))
      : [];
  } catch {
    return [];
  }
}

// Validation Functions
const validateEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const validateUsername = (username) => /^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d]{5,}$/.test(username);
const validateName = (name) => /^[a-zA-Z\s]+\s+[a-zA-Z\s]+$/.test(name);
const validatePassword = (password) => /^(?=.*[a-zA-Z])(?=.*\d)(?=.*[!@#$%^&*])[a-zA-Z\d!@#$%^&*]{12,}$/.test(password);
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

// Endpoints
app.post('/api/affiliate/register', registerLimiter, async (req, res) => {
  try {
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
    let refCode = Math.random().toString(36).substring(2, 10).toUpperCase();
    let attempts = 0;
    while (affiliates.some(a => a.RefCode === refCode) && attempts < 3) {
      refCode = Math.random().toString(36).substring(2, 10 + attempts * 4).toUpperCase();
      attempts++;
    }
    if (affiliates.some(a => a.RefCode === refCode)) {
      return res.status(500).json({ success: false, message: 'Failed to generate unique referral code' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const affiliate = {
      Email: email,
      Username: username,
      Name: name,
      JoinDate: new Date().toISOString(),
      RefCode: refCode,
      Password: hashedPassword,
      Statusjson: { status: 'active' },
      LinkClicks: 0,
      TotalSales: 0,
      TotalSalesMonthly: 0,
      CurrentBalance: 0,
      WithdrawnTotal: 0,
      WithdrawalsJSON: [],
      RewardsJSON: [],
      NotificationsJSON: [],
      ResetJSON: [],
      LeaderboardJSON: { previousRank: 0, currentRank: 0 },
      MpesaDetails: {}
    };
    await sheets.spreadsheets.values.append({
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: 'all affiliates!A:R',
      valueInputOption: 'RAW',
      resource: {
        values: [[
          affiliate.Email, affiliate.Username, affiliate.Name, affiliate.JoinDate,
          affiliate.RefCode, affiliate.Password, JSON.stringify(affiliate.Statusjson),
          affiliate.LinkClicks, affiliate.TotalSales, affiliate.TotalSalesMonthly,
          affiliate.CurrentBalance, affiliate.WithdrawnTotal,
          JSON.stringify(affiliate.WithdrawalsJSON), JSON.stringify(affiliate.RewardsJSON),
          JSON.stringify(affiliate.NotificationsJSON), JSON.stringify(affiliate.ResetJSON),
          JSON.stringify(affiliate.LeaderboardJSON), JSON.stringify(affiliate.MpesaDetails)
        ]]
      }
    });
    await logTransaction(email, 'register', { username, refCode });
    const token = jwt.sign({ email, username, role: 'affiliate' }, JWT_SECRET, { expiresIn: '7d' });
    await updateCache();
    res.json({ success: true, token, data: { name, username, refCode } });
  } catch (error) {
    console.error('Error in /api/affiliate/register:', error.message);
    res.status(500).json({ success: false, message: 'Failed to register affiliate', error: error.message });
  }
});

app.post('/api/affiliate/login', loginLimiter, async (req, res) => {
  try {
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
  } catch (error) {
    console.error('Error in /api/affiliate/login:', error.message);
    res.status(500).json({ success: false, message: 'Failed to login', error: error.message });
  }
});

app.post('/api/admin/affiliate/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const settings = await fetchSettings();
    if (email !== settings.adminEmail || password !== settings.adminPassword) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    const token = jwt.sign({ email, role: 'admin' }, JWT_SECRET, { expiresIn: '7d' });
    if (wsClients.has('admin')) {
      wsClients.get('admin').send(JSON.stringify({ type: 'logout', message: 'Session disconnected, please re-login' }));
      wsClients.delete('admin');
    }
    await logTransaction(email, 'admin_login', {});
    res.json({ success: true, token });
  } catch (error) {
    console.error('Error in /api/admin/affiliate/login:', error.message);
    res.status(500).json({ success: false, message: 'Failed to login admin', error: error.message });
  }
});

app.post('/api/affiliate/reset-password', resetLimiter, async (req, res) => {
  try {
    const { name, email, username, lastWithdrawalAmount, description } = req.body;
    const sanitizedDescription = sanitizeHtml(description);
    if (!validateName(name) || !validateEmail(email) || !validateUsername(username) || sanitizedDescription.length > 100) {
      return res.status(400).json({ success: false, message: 'Invalid input' });
    }
    const affiliates = await fetchAffiliates();
    const affiliate = affiliates.find(a => a.Email === email && a.Username === username);
    if (!affiliate) {
      return res.status(400).json({ success: false, message: 'Email or username does not exist' });
    }
    affiliate.ResetJSON.unshift({
      status: 'pending',
      timestamp: new Date().toISOString(),
      description: sanitizedDescription,
      lastWithdrawalAmount: lastWithdrawalAmount || 0,
      oneTimePassword: ''
    });
    if (affiliate.ResetJSON.length > 20) {
      affiliate.ResetJSON = affiliate.ResetJSON.slice(0, 20);
    }
    await updateAffiliateField(affiliate.Email, 'ResetJSON', affiliate.ResetJSON);
    await logTransaction(email, 'reset_password_request', { username, lastWithdrawalAmount, description: sanitizedDescription });
    await sendEmail(
      APP_EMAIL,
      'Password Reset Request',
      `User: ${email}, Username: ${username}, Name: ${name}, Last Withdrawal: ${lastWithdrawalAmount || 0}, Description: ${sanitizedDescription}`
    );
    res.json({ success: true, message: 'Reset request submitted' });
  } catch (error) {
    console.error('Error in /api/affiliate/reset-password:', error.message);
    res.status(500).json({ success: false, message: 'Failed to submit reset request', error: error.message });
  }
});

app.get('/api/affiliate/data', authenticateAffiliate, async (req, res) => {
  try {
    const affiliate = cachedDataAffiliate.affiliates.find(a => a.Email === req.user.email);
    if (!affiliate) return res.status(401).json({ success: false, message: 'Unauthorized' });
    const leaderboard = cachedDataAffiliate.affiliates
      .filter(a => a.Statusjson.status === 'active')
      .sort((a, b) => b.TotalSalesMonthly - a.TotalSalesMonthly)
      .slice(0, 10)
      .map((a, i) => ({
        rank: i + 1,
        name: a.Name,
        email: a.Email,
        monthlySales: a.TotalSalesMonthly,
        momentum: a.LeaderboardJSON.currentRank < a.LeaderboardJSON.previousRank ? 'up' :
                  a.LeaderboardJSON.currentRank > a.LeaderboardJSON.previousRank ? 'down' : 'same'
      }));
    res.json({
      success: true,
      data: {
        name: affiliate.Name,
        refCode: affiliate.RefCode,
        linkClicks: affiliate.LinkClicks,
        totalSales: affiliate.TotalSales,
        totalSalesMonthly: affiliate.TotalSalesMonthly,
        currentBalance: affiliate.CurrentBalance,
        withdrawnTotal: affiliate.WithdrawnTotal,
        withdrawalsJSON: affiliate.WithdrawalsJSON,
        rewardsJSON: affiliate.RewardsJSON,
        notificationsJSON: affiliate.NotificationsJSON,
        resetJSON: affiliate.ResetJSON,
        leaderboardJSON: affiliate.LeaderboardJSON,
        leaderboard,
        news: cachedDataAffiliate.news,
        commissionRate: cachedDataAffiliate.settings.commissionRate
      }
    });
  } catch (error) {
    console.error('Error in /api/affiliate/data:', error.message);
    res.status(500).json({ success: false, message: 'Failed to fetch data', error: error.message });
  }
});

app.get('/api/admin/affiliate/affiliates', authenticateAdmin, async (req, res) => {
  try {
    res.json({ success: true, affiliates: cachedDataAffiliate.affiliates });
  } catch (error) {
    console.error('Error in /api/admin/affiliate/affiliates:', error.message);
    res.status(500).json({ success: false, message: 'Failed to fetch affiliates', error: error.message });
  }
});

app.get('/api/admin/affiliate/withdrawals', authenticateAdmin, async (req, res) => {
  try {
    const withdrawals = cachedDataAffiliate.affiliates
      .flatMap(a => a.WithdrawalsJSON
        .filter(w => w.status === 'Pending')
        .map(w => ({ ...w, email: a.Email, name: a.Name }))
      );
    res.json({ success: true, withdrawals });
  } catch (error) {
    console.error('Error in /api/admin/affiliate/withdrawals:', error.message);
    res.status(500).json({ success: false, message: 'Failed to fetch withdrawals', error: error.message });
  }
});

app.get('/api/admin/affiliate/reset-passwords', authenticateAdmin, async (req, res) => {
  try {
    const requests = cachedDataAffiliate.affiliates
      .flatMap(a => a.ResetJSON
        .filter(r => r.status === 'pending')
        .map(r => ({ ...r, email: a.Email, username: a.Username, name: a.Name }))
      );
    res.json({ success: true, requests });
  } catch (error) {
    console.error('Error in /api/admin/affiliate/reset-passwords:', error.message);
    res.status(500).json({ success: false, message: 'Failed to fetch reset requests', error: error.message });
  }
});

app.get('/api/admin/affiliate/staticpages', authenticateAdmin, async (req, res) => {
  try {
    res.json({ success: true, pages: cachedDataAffiliate.staticPages });
  } catch (error) {
    console.error('Error in /api/admin/affiliate/staticpages:', error.message);
    res.status(500).json({ success: false, message: 'Failed to fetch static pages', error: error.message });
  }
});

app.get('/api/affiliate/static-page/:slug', async (req, res) => {
  try {
    const page = cachedDataAffiliate.staticPages.find(p => p.Slug === req.params.slug);
    if (!page) return res.status(404).json({ success: false, message: 'Page not found' });
    res.json({ success: true, page });
  } catch (error) {
    console.error('Error in /api/affiliate/static-page:', error.message);
    res.status(500).json({ success: false, message: 'Failed to fetch page', error: error.message });
  }
});

app.post('/api/affiliate/track-click', async (req, res) => {
  try {
    const { refCode } = req.body;
    const affiliates = await fetchAffiliates();
    const affiliate = affiliates.find(a => a.RefCode === refCode);
    if (!affiliate) return res.status(400).json({ success: false, message: 'Invalid refCode' });
    affiliate.LinkClicks += 1;
    await updateAffiliateField(affiliate.Email, 'LinkClicks', affiliate.LinkClicks);
    if (wsClients.has(affiliate.Email)) {
      wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'update', data: affiliate }));
    }
    res.json({ success: true });
  } catch (error) {
    console.error('Error in /api/affiliate/track-click:', error.message);
    res.status(500).json({ success: false, message: 'Failed to track click', error: error.message });
  }
});

app.post('/api/affiliate/confirmed-sale', async (req, res) => {
  try {
    const { refCode, amount, item, apiKey } = req.body;
    if (apiKey !== AFFILIATE_API_KEY || !refCode || amount <= 0) {
      return res.status(401).json({ success: false, message: 'Invalid API key or data' });
    }
    const affiliates = await fetchAffiliates();
    const affiliate = affiliates.find(a => a.RefCode === refCode);
    if (!affiliate) return res.status(400).json({ success: false, message: 'Invalid refCode' });
    const commission = amount * cachedDataAffiliate.settings.commissionRate;
    affiliate.TotalSales += 1;
    affiliate.TotalSalesMonthly += 1;
    affiliate.CurrentBalance += commission;
    affiliate.NotificationsJSON.unshift({
      id: `NOTIF${Date.now()}`,
      read: false,
      colour: 'green',
      message: `Sale confirmed: ${amount} KES for ${item}, Commission: ${commission} KES`,
      timestamp: new Date().toISOString()
    });
    if (affiliate.NotificationsJSON.length > 20) {
      affiliate.NotificationsJSON = affiliate.NotificationsJSON.slice(0, 20);
    }
    affiliate.LeaderboardJSON.previousRank = affiliate.LeaderboardJSON.currentRank;
    const rankedAffiliates = affiliates
      .filter(a => a.Statusjson.status === 'active')
      .sort((a, b) => b.TotalSalesMonthly - a.TotalSalesMonthly);
    affiliate.LeaderboardJSON.currentRank = rankedAffiliates.findIndex(a => a.Email === affiliate.Email) + 1;
    if (affiliate.LeaderboardJSON.previousRank && affiliate.LeaderboardJSON.currentRank !== affiliate.LeaderboardJSON.previousRank) {
      affiliate.NotificationsJSON.unshift({
        id: `NOTIF${Date.now()}`,
        read: false,
        colour: affiliate.LeaderboardJSON.currentRank < affiliate.LeaderboardJSON.previousRank ? 'green' : 'red',
        message: affiliate.LeaderboardJSON.currentRank < affiliate.LeaderboardJSON.previousRank
          ? 'You moved up in the leaderboard!'
          : 'You moved down in the leaderboard.',
        timestamp: new Date().toISOString()
      });
    }
    await updateAffiliateField(affiliate.Email, 'TotalSales', affiliate.TotalSales);
    await updateAffiliateField(affiliate.Email, 'TotalSalesMonthly', affiliate.TotalSalesMonthly);
    await updateAffiliateField(affiliate.Email, 'CurrentBalance', affiliate.CurrentBalance);
    await updateAffiliateField(affiliate.Email, 'NotificationsJSON', affiliate.NotificationsJSON);
    await updateAffiliateField(affiliate.Email, 'LeaderboardJSON', affiliate.LeaderboardJSON);
    await logTransaction(affiliate.Email, 'sale_confirmed', { refCode, amount, commission, item });
    if (wsClients.has(affiliate.Email)) {
      wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'update', data: affiliate }));
      wsClients.get(affiliate.Email).send(JSON.stringify({
        type: 'notification',
        data: affiliate.NotificationsJSON[0]
      }));
    }
    res.json({ success: true });
  } catch (error) {
    console.error('Error in /api/affiliate/confirmed-sale:', error.message);
    res.status(500).json({ success: false, message: 'Failed to process sale', error: error.message });
  }
});

app.post('/api/affiliate/request-withdrawal', authenticateAffiliate, async (req, res) => {
  try {
    const { amount, mpesaNumber, mpesaName, reuseDetails, password } = req.body;
    if (!validateMpesaNumber(mpesaNumber) || !validateName(mpesaName) || amount < 100 || amount > cachedDataAffiliate.affiliates.find(a => a.Email === req.user.email).CurrentBalance) {
      return res.status(400).json({ success: false, message: 'Invalid withdrawal details or insufficient balance' });
    }
    const affiliates = await fetchAffiliates();
    const affiliate = affiliates.find(a => a.Email === req.user.email);
    if (!affiliate || !(await bcrypt.compare(password, affiliate.Password))) {
      return res.status(401).json({ success: false, message: 'Incorrect password' });
    }
    affiliate.CurrentBalance -= amount;
    affiliate.WithdrawnTotal += amount;
    const withdrawal = {
      date: new Date().toISOString(),
      amount,
      mpesaNumber,
      mpesaName,
      status: 'Pending',
      mpesaRef: ''
    };
    affiliate.WithdrawalsJSON.unshift(withdrawal);
    if (affiliate.WithdrawalsJSON.length > 20) {
      affiliate.WithdrawalsJSON = affiliate.WithdrawalsJSON.slice(0, 20);
    }
    if (reuseDetails) {
      affiliate.MpesaDetails = { mpesaNumber, mpesaName };
    }
    affiliate.NotificationsJSON.unshift({
      id: `NOTIF${Date.now()}`,
      read: false,
      colour: 'green',
      message: 'Withdrawal submitted. You’ll receive it soon as processed.',
      timestamp: new Date().toISOString()
    });
    if (affiliate.NotificationsJSON.length > 20) {
      affiliate.NotificationsJSON = affiliate.NotificationsJSON.slice(0, 20);
    }
    await updateAffiliateField(affiliate.Email, 'CurrentBalance', affiliate.CurrentBalance);
    await updateAffiliateField(affiliate.Email, 'WithdrawnTotal', affiliate.WithdrawnTotal);
    await updateAffiliateField(affiliate.Email, 'WithdrawalsJSON', affiliate.WithdrawalsJSON);
    await updateAffiliateField(affiliate.Email, 'NotificationsJSON', affiliate.NotificationsJSON);
    if (reuseDetails) {
      await updateAffiliateField(affiliate.Email, 'MpesaDetails', affiliate.MpesaDetails);
    }
    await logTransaction(affiliate.Email, 'request_withdrawal', { amount, mpesaNumber });
    await sendEmail(
      APP_EMAIL,
      'Withdrawal Request',
      `User: ${affiliate.Email}, Amount: ${amount} KES, MPESA Number: ${mpesaNumber}, MPESA Name: ${mpesaName}`
    );
    if (wsClients.has(affiliate.Email)) {
      wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'update', data: affiliate }));
      wsClients.get(affiliate.Email).send(JSON.stringify({
        type: 'notification',
        data: affiliate.NotificationsJSON[0]
      }));
    }
    res.json({ success: true, withdrawal });
  } catch (error) {
    console.error('Error in /api/affiliate/request-withdrawal:', error.message);
    res.status(500).json({ success: false, message: 'Failed to request withdrawal', error: error.message });
  }
});

app.post('/api/admin/affiliate/withdrawals/:action', authenticateAdmin, async (req, res) => {
  try {
    const { action } = req.params;
    const { email, withdrawalId, status, refCode } = req.body;
    if (!['done', 'dispute'].includes(action) || !['Done', 'Failed'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid action or status' });
    }
    const affiliates = await fetchAffiliates();
    const affiliate = affiliates.find(a => a.Email === email);
    if (!affiliate) return res.status(400).json({ success: false, message: 'Affiliate not found' });
    const withdrawal = affiliate.WithdrawalsJSON.find(w => w.date === withdrawalId);
    if (!withdrawal) return res.status(400).json({ success: false, message: 'Withdrawal not found' });
    if (action === 'done' && !refCode) {
      return res.status(400).json({ success: false, message: 'Reference code required for Done status' });
    }
    withdrawal.status = status;
    if (action === 'done') {
      withdrawal.mpesaRef = refCode;
      affiliate.NotificationsJSON.unshift({
        id: `NOTIF${Date.now()}`,
        read: false,
        colour: 'green',
        message: `Payment sent. M-PESA Ref: ${refCode}`,
        timestamp: new Date().toISOString()
      });
    } else {
      affiliate.CurrentBalance += withdrawal.amount;
      affiliate.NotificationsJSON.unshift({
        id: `NOTIF${Date.now()}`,
        read: false,
        colour: 'red',
        message: 'Payment failed. Contact support',
        timestamp: new Date().toISOString()
      });
      await updateAffiliateField(affiliate.Email, 'CurrentBalance', affiliate.CurrentBalance);
    }
    if (affiliate.NotificationsJSON.length > 20) {
      affiliate.NotificationsJSON = affiliate.NotificationsJSON.slice(0, 20);
    }
    await updateAffiliateField(affiliate.Email, 'WithdrawalsJSON', affiliate.WithdrawalsJSON);
    await updateAffiliateField(affiliate.Email, 'NotificationsJSON', affiliate.NotificationsJSON);
    await logTransaction(email, `withdrawal_${action}`, { withdrawalId, status, refCode });
    if (wsClients.has(affiliate.Email)) {
      wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'update', data: affiliate }));
      wsClients.get(affiliate.Email).send(JSON.stringify({
        type: 'notification',
        data: affiliate.NotificationsJSON[0]
      }));
    }
    if (wsClients.has('admin')) {
      wsClients.get('admin').send(JSON.stringify({
        type: 'withdrawal_updated',
        data: { email, withdrawalId, status }
      }));
    }
    res.json({ success: true });
  } catch (error) {
    console.error('Error in /api/admin/affiliate/withdrawals:', error.message);
    res.status(500).json({ success: false, message: 'Failed to process withdrawal', error: error.message });
  }
});

app.post('/api/admin/affiliate/rewards', authenticateAdmin, async (req, res) => {
  try {
    const { type, percentage, amount, recipients } = req.body;
    const affiliates = await fetchAffiliates();
    let rewardedAffiliates = [];
    if (type === 'percentage') {
      if (percentage < 0 || percentage > 1) {
        return res.status(400).json({ success: false, message: 'Invalid percentage' });
      }
      rewardedAffiliates = affiliates
        .filter(a => a.Statusjson.status === 'active')
        .sort((a, b) => b.TotalSalesMonthly - a.TotalSalesMonthly)
        .slice(0, 10);
      for (const affiliate of rewardedAffiliates) {
        const reward = affiliate.TotalSalesMonthly * percentage;
        if (reward >= 100) {
          affiliate.CurrentBalance += reward;
          affiliate.RewardsJSON.unshift({
            date: new Date().toISOString(),
            type: 'leaderboard',
            amount: reward,
            description: `You were credited ${percentage * 100}% reward of your current sales this month`
          });
          affiliate.NotificationsJSON.unshift({
            id: `NOTIF${Date.now()}`,
            read: false,
            colour: 'blue',
            message: `Congratulations, you have been awarded ${reward} KES. Leaderboard awards`,
            timestamp: new Date().toISOString()
          });
          if (affiliate.NotificationsJSON.length > 20) {
            affiliate.NotificationsJSON = affiliate.NotificationsJSON.slice(0, 20);
          }
          if (affiliate.RewardsJSON.length > 20) {
            affiliate.RewardsJSON = affiliate.RewardsJSON.slice(0, 20);
          }
          await updateAffiliateField(affiliate.Email, 'CurrentBalance', affiliate.CurrentBalance);
          await updateAffiliateField(affiliate.Email, 'RewardsJSON', affiliate.RewardsJSON);
          await updateAffiliateField(affiliate.Email, 'NotificationsJSON', affiliate.NotificationsJSON);
          if (wsClients.has(affiliate.Email)) {
            wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'update', data: affiliate }));
            wsClients.get(affiliate.Email).send(JSON.stringify({
              type: 'notification',
              data: affiliate.NotificationsJSON[0]
            }));
          }
        }
      }
      await sheets.spreadsheets.values.append({
        spreadsheetId: ADMIN_SHEET_ID,
        range: 'News!A:C',
        valueInputOption: 'RAW',
        resource: {
          values: [[`NEWS${Date.now()}`, 'Rewards have been issued for the leaderboard', new Date().toISOString()]]
        }
      });
    } else if (type === 'spot') {
      if (amount < 100 || !Array.isArray(recipients)) {
        return res.status(400).json({ success: false, message: 'Invalid amount or recipients' });
      }
      rewardedAffiliates = affiliates.filter(a => recipients.includes(a.Email) && a.Statusjson.status === 'active');
      for (const affiliate of rewardedAffiliates) {
        affiliate.CurrentBalance += amount;
        affiliate.RewardsJSON.unshift({
          date: new Date().toISOString(),
          type: 'spot',
          amount,
          description: `Spot reward of ${amount} KES`
        });
        affiliate.NotificationsJSON.unshift({
          id: `NOTIF${Date.now()}`,
          read: false,
          colour: 'blue',
          message: `Congratulations, you have been awarded ${amount} KES`,
          timestamp: new Date().toISOString()
        });
        if (affiliate.NotificationsJSON.length > 20) {
          affiliate.NotificationsJSON = affiliate.NotificationsJSON.slice(0, 20);
        }
        if (affiliate.RewardsJSON.length > 20) {
          affiliate.RewardsJSON = affiliate.RewardsJSON.slice(0, 20);
        }
        await updateAffiliateField(affiliate.Email, 'CurrentBalance', affiliate.CurrentBalance);
        await updateAffiliateField(affiliate.Email, 'RewardsJSON', affiliate.RewardsJSON);
        await updateAffiliateField(affiliate.Email, 'NotificationsJSON', affiliate.NotificationsJSON);
        if (wsClients.has(affiliate.Email)) {
          wsClients.get(affiliate.Email).send(JSON.stringify({ type: 'update', data: affiliate }));
          wsClients.get(affiliate.Email).send(JSON.stringify({
            type: 'notification',
            data: affiliate.NotificationsJSON[0]
          }));
        }
      }
      await sheets.spreadsheets.values.append({
        spreadsheetId: ADMIN_SHEET_ID,
        range: 'News!A:C',
        valueInputOption: 'RAW',
        resource: {
          values: [[`NEWS${Date.now()}`, 'Rewards have been issued for selected affiliates', new Date().toISOString()]]
        }
      });
    } else {
      return res.status(400).json({ success: false, message: 'Invalid reward type' });
    }
    await logTransaction('admin', `rewards_${type}`, { percentage, amount, recipients: rewardedAffiliates.map(a => a.Email) });
    await updateCache();
    if (wsClients.has('admin')) {
      wsClients.get('admin').send(JSON.stringify({
        type: 'rewards_issued',
        data: { type, recipients: rewardedAffiliates.map(a => a.Email) }
      }));
    }
    res.json({ success: true });
  } catch (error) {
    console.error('Error in /api/admin/affiliate/rewards:', error.message);
    res.status(500).json({ success: false, message: 'Failed to apply rewards', error: error.message });
  }
});

app.post('/api/admin/affiliate/staticpages', authenticateAdmin, async (req, res) => {
  try {
    const { slug, title, content } = req.body;
    const sanitizedContent = sanitizeHtml(content);
    if (!slug || !title || !sanitizedContent) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }
    const staticPages = await fetchStaticPages();
    const existingPage = staticPages.find(p => p.Slug === slug);
    if (existingPage) {
      const pageIndex = staticPages.findIndex(p => p.Slug === slug) + 2;
      await sheets.spreadsheets.values.update({
        spreadsheetId: ADMIN_SHEET_ID,
        range: `staticPagesAffiliate!A${pageIndex}:C${pageIndex}`,
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
    await logTransaction('admin', 'update_static_page', { slug, title });
    await updateCache();
    cachedDataAffiliate.affiliates.forEach(affiliate => {
      if (wsClients.has(affiliate.Email)) {
        wsClients.get(affiliate.Email).send(JSON.stringify({
          type: 'static_page_updated',
          data: { slug, title }
        }));
      }
    });
    if (wsClients.has('admin')) {
      wsClients.get('admin').send(JSON.stringify({
        type: 'static_page_updated',
        data: { slug, title }
      }));
    }
    res.json({ success: true, page: { slug, title, content: sanitizedContent } });
  } catch (error) {
    console.error('Error in /api/admin/affiliate/staticpages:', error.message);
    res.status(500).json({ success: false, message: 'Failed to update static page', error: error.message });
  }
});

app.post('/api/admin/affiliate/staticpages/delete', authenticateAdmin, async (req, res) => {
  try {
    const { slug } = req.body;
    const staticPages = await fetchStaticPages();
    const pageIndex = staticPages.findIndex(p => p.Slug === slug);
    if (pageIndex === -1) {
      return res.status(404).json({ success: false, message: 'Page not found' });
    }
    const rowIndex = pageIndex + 2;
    await sheets.spreadsheets.values.clear({
      spreadsheetId: ADMIN_SHEET_ID,
      range: `staticPagesAffiliate!A${rowIndex}:C${rowIndex}`
    });
    await logTransaction('admin', 'delete_static_page', { slug });
    await updateCache();
    cachedDataAffiliate.affiliates.forEach(affiliate => {
      if (wsClients.has(affiliate.Email)) {
        wsClients.get(affiliate.Email).send(JSON.stringify({
          type: 'static_page_deleted',
          data: { slug }
        }));
      }
    });
    if (wsClients.has('admin')) {
      wsClients.get('admin').send(JSON.stringify({
        type: 'static_page_deleted',
        data: { slug }
      }));
    }
    res.json({ success: true });
  } catch (error) {
    console.error('Error in /api/admin/affiliate/staticpages/delete:', error.message);
    res.status(500).json({ success: false, message: 'Failed to delete static page', error: error.message });
  }
});

app.post('/api/admin/affiliate/communication', authenticateAdmin, async (req, res) => {
  try {
    const { type, message, enabled, filter } = req.body;
    if (type === 'urgent') {
      const settings = await fetchSettings();
      settings.urgentPopup = { message, enabled };
      await sheets.spreadsheets.values.update({
        spreadsheetId: ADMIN_SHEET_ID,
        range: 'settingsAffiliate!A2:B',
        valueInputOption: 'RAW',
        resource: {
          values: [
            ['supportEmail', settings.supportEmail],
            ['copyrightText', settings.copyrightText],
            ['whatsappLink', settings.whatsappLink],
            ['commissionRate', JSON.stringify(settings.commissionRate)],
            ['logoUrl', settings.logoUrl],
            ['adminEmail', settings.adminEmail],
            ['adminPassword', settings.adminPassword],
            ['urgentPopup', JSON.stringify(settings.urgentPopup)]
          ]
        }
      });
      await logTransaction('admin', 'update_urgent_message', { message, enabled });
      await updateCache();
      cachedDataAffiliate.affiliates.forEach(affiliate => {
        if (wsClients.has(affiliate.Email)) {
          wsClients.get(affiliate.Email).send(JSON.stringify({
            type: 'settings_updated',
            data: { urgentPopup: settings.urgentPopup }
          }));
        }
      });
      res.json({ success: true, message: 'Urgent message updated' });
    } else if (type === 'news') {
      const newsId = `NEWS${Date.now()}`;
      await sheets.spreadsheets.values.append({
        spreadsheetId: ADMIN_SHEET_ID,
        range: 'News!A:C',
        valueInputOption: 'RAW',
        resource: {
          values: [[newsId, message, new Date().toISOString()]]
        }
      });
      await logTransaction('admin', 'send_news', { message, filter });
      await updateCache();
      cachedDataAffiliate.affiliates
        .filter(a => filter === 'all' || a.Statusjson.status === 'active')
        .forEach(affiliate => {
          if (wsClients.has(affiliate.Email)) {
            wsClients.get(affiliate.Email).send(JSON.stringify({
              type: 'news',
              data: { Id: newsId, Message: message, Timestamp: new Date().toISOString() }
            }));
          }
        });
      res.json({ success: true, message: 'News sent' });
    } else {
      res.status(400).json({ success: false, message: 'Invalid communication type' });
    }
  } catch (error) {
    console.error('Error in /api/admin/affiliate/communication:', error.message);
    res.status(500).json({ success: false, message: 'Failed to process communication', error: error.message });
  }
});

app.post('/api/admin/affiliate/settings', authenticateAdmin, async (req, res) => {
  try {
    const { supportEmail, copyrightText, whatsappLink, commissionRate, logoUrl, adminEmail, adminPassword } = req.body;
    if (!validateEmail(supportEmail) || !validateEmail(adminEmail) || (commissionRate && (commissionRate < 0 || commissionRate > 1))) {
      return res.status(400).json({ success: false, message: 'Invalid input' });
    }
    const settings = await fetchSettings();
    const updatedSettings = {
      supportEmail: supportEmail || settings.supportEmail,
      copyrightText: copyrightText || settings.copyrightText,
      whatsappLink: whatsappLink || settings.whatsappLink,
      commissionRate: commissionRate || settings.commissionRate,
      logoUrl: logoUrl || settings.logoUrl,
      adminEmail: adminEmail || settings.adminEmail,
      adminPassword: adminPassword || settings.adminPassword,
      urgentPopup: settings.urgentPopup
    };
    await sheets.spreadsheets.values.update({
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'settingsAffiliate!A2:B',
      valueInputOption: 'RAW',
      resource: {
        values: [
          ['supportEmail', updatedSettings.supportEmail],
          ['copyrightText', updatedSettings.copyrightText],
          ['whatsappLink', updatedSettings.whatsappLink],
          ['commissionRate', JSON.stringify(updatedSettings.commissionRate)],
          ['logoUrl', updatedSettings.logoUrl],
          ['adminEmail', updatedSettings.adminEmail],
          ['adminPassword', updatedSettings.adminPassword],
          ['urgentPopup', JSON.stringify(updatedSettings.urgentPopup)]
        ]
      }
    });
    await logTransaction('admin', 'update_settings', updatedSettings);
    await updateCache();
    cachedDataAffiliate.affiliates.forEach(affiliate => {
      if (wsClients.has(affiliate.Email)) {
        wsClients.get(affiliate.Email).send(JSON.stringify({
          type: 'settings_updated',
          data: updatedSettings
        }));
      }
    });
    if (wsClients.has('admin')) {
      wsClients.get('admin').send(JSON.stringify({
        type: 'settings_updated',
        data: updatedSettings
      }));
    }
    res.json({ success: true, settings: updatedSettings });
  } catch (error) {
    console.error('Error in /api/admin/affiliate/settings:', error.message);
    res.status(500).json({ success: false, message: 'Failed to update settings', error: error.message });
  }
});

app.post('/api/affiliate/update-password', authenticateAffiliate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!validatePassword(newPassword)) {
      return res.status(400).json({ success: false, message: 'New password must be at least 12 characters with letters, numbers, and special characters' });
    }
    const affiliates = await fetchAffiliates();
    const affiliate = affiliates.find(a => a.Email === req.user.email);
    if (!affiliate || !(await bcrypt.compare(currentPassword, affiliate.Password))) {
      return res.status(401).json({ success: false, message: 'Incorrect current password' });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    affiliate.Password = hashedPassword;
    await updateAffiliateField(affiliate.Email, 'Password', hashedPassword);
    await logTransaction(affiliate.Email, 'update_password', {});
    await sendEmail(
      affiliate.Email,
      'Password Updated',
      'Your affiliate account password has been successfully updated.'
    );
    if (wsClients.has(affiliate.Email)) {
      wsClients.get(affiliate.Email).send(JSON.stringify({
        type: 'notification',
        data: {
          id: `NOTIF${Date.now()}`,
          read: false,
          colour: 'blue',
          message: 'Your password has been updated successfully',
          timestamp: new Date().toISOString()
        }
      }));
      wsClients.get(affiliate.Email).send(JSON.stringify({
        type: 'logout',
        message: 'Password changed, please re-login'
      }));
      wsClients.delete(affiliate.Email);
    }
    res.json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    console.error('Error in /api/affiliate/update-password:', error.message);
    res.status(500).json({ success: false, message: 'Failed to update password', error: error.message });
  }
});

app.post('/api/admin/affiliate/reset-password', authenticateAdmin, async (req, res) => {
  try {
    const { email, status, password } = req.body;
    if (status === 'approved' && !validatePassword(password)) {
      return res.status(400).json({ success: false, message: 'New password must be at least 12 characters with letters, numbers, and special characters' });
    }
    const affiliates = await fetchAffiliates();
    const affiliate = affiliates.find(a => a.Email === email);
    if (!affiliate) return res.status(400).json({ success: false, message: 'Affiliate not found' });
    const resetEntry = affiliate.ResetJSON.find(r => r.status === 'pending');
    if (!resetEntry) return res.status(400).json({ success: false, message: 'No pending reset request found' });
    resetEntry.status = status;
    if (status === 'approved') {
      resetEntry.oneTimePassword = password;
      const hashedPassword = await bcrypt.hash(password, 10);
      affiliate.Password = hashedPassword;
      await updateAffiliateField(affiliate.Email, 'Password', hashedPassword);
      await sendEmail(
        affiliate.Email,
        'Password Reset',
        `Your password has been reset. Your new password is: ${password}. Please log in and change it immediately.`
      );
      affiliate.NotificationsJSON.unshift({
        id: `NOTIF${Date.now()}`,
        read: false,
        colour: 'blue',
        message: 'Your password has been reset by admin. Please check your email.',
        timestamp: new Date().toISOString()
      });
    } else {
      affiliate.NotificationsJSON.unshift({
        id: `NOTIF${Date.now()}`,
        read: false,
        colour: 'red',
        message: 'Your password reset request was declined. Contact support.',
        timestamp: new Date().toISOString()
      });
    }
    if (affiliate.NotificationsJSON.length > 20) {
      affiliate.NotificationsJSON = affiliate.NotificationsJSON.slice(0, 20);
    }
    affiliate.ResetJSON = affiliate.ResetJSON.filter(r => (new Date() - new Date(r.timestamp)) / (1000 * 60 * 60) < 24);
    await updateAffiliateField(affiliate.Email, 'ResetJSON', affiliate.ResetJSON);
    await updateAffiliateField(affiliate.Email, 'NotificationsJSON', affiliate.NotificationsJSON);
    await logTransaction(email, 'reset_password_action', { status });
    if (wsClients.has(affiliate.Email)) {
      wsClients.get(affiliate.Email).send(JSON.stringify({
        type: 'notification',
        data: affiliate.NotificationsJSON[0]
      }));
      if (status === 'approved') {
        wsClients.get(affiliate.Email).send(JSON.stringify({
          type: 'logout',
          message: 'Password reset, please re-login'
        }));
        wsClients.delete(affiliate.Email);
      }
    }
    res.json({ success: true, message: 'Reset request processed' });
  } catch (error) {
    console.error('Error in /api/admin/affiliate/reset-password:', error.message);
    res.status(500).json({ success: false, message: 'Failed to process reset request', error: error.message });
  }
});

app.post('/api/admin/affiliate/update-status', authenticateAdmin, async (req, res) => {
  try {
    const { email, status } = req.body;
    if (!['active', 'blocked', 'deleted'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }
    const affiliates = await fetchAffiliates();
    const affiliate = affiliates.find(a => a.Email === email);
    if (!affiliate) return res.status(400).json({ success: false, message: 'Affiliate not found' });
    affiliate.Statusjson = { status };
    await updateAffiliateField(affiliate.Email, 'Statusjson', affiliate.Statusjson);
    await logTransaction(affiliate.Email, 'update_status', { status });
    await sendEmail(
      affiliate.Email,
      `Account Status Updated: ${status.charAt(0).toUpperCase() + status.slice(1)}`,
      `Your affiliate account status has been updated to ${status}. Please contact ${cachedDataAffiliate.settings.supportEmail} for any questions.`
    );
    if (wsClients.has(affiliate.Email)) {
      wsClients.get(affiliate.Email).send(JSON.stringify({
        type: 'notification',
        data: {
          id: `NOTIF${Date.now()}`,
          read: false,
          colour: status === 'active' ? 'green' : 'red',
          message: `Your account status has been updated to ${status}`,
          timestamp: new Date().toISOString()
        }
      }));
      if (status !== 'active') {
        wsClients.get(affiliate.Email).send(JSON.stringify({
          type: 'logout',
          message: 'Your account status has changed. Please re-login.'
        }));
        wsClients.delete(affiliate.Email);
      }
    }
    if (wsClients.has('admin')) {
      wsClients.get('admin').send(JSON.stringify({
        type: 'affiliate_status_updated',
        data: { email, status }
      }));
    }
    res.json({ success: true, message: `Affiliate status updated to ${status}` });
  } catch (error) {
    console.error('Error in /api/admin/affiliate/update-status:', error.message);
    res.status(500).json({ success: false, message: 'Failed to update status', error: error.message });
  }
});

app.post('/api/affiliate/mark-notification', authenticateAffiliate, async (req, res) => {
  try {
    const { notificationId } = req.body;
    if (!notificationId) {
      return res.status(400).json({ success: false, message: 'Notification ID required' });
    }
    const affiliates = await fetchAffiliates();
    const affiliate = affiliates.find(a => a.Email === req.user.email);
    if (!affiliate) {
      return res.status(401).json({ success: false, message: 'Affiliate not found' });
    }
    const notification = affiliate.NotificationsJSON.find(n => n.id === notificationId);
    if (!notification) {
      return res.status(400).json({ success: false, message: 'Notification not found' });
    }
    notification.read = true;
    await updateAffiliateField(affiliate.Email, 'NotificationsJSON', affiliate.NotificationsJSON);
    await logTransaction(affiliate.Email, 'mark_notification', { notificationId });
    if (wsClients.has(affiliate.Email)) {
      wsClients.get(affiliate.Email).send(JSON.stringify({
        type: 'update',
        data: affiliate
      }));
    }
    res.json({ success: true, message: 'Notification marked as read' });
  } catch (error) {
    console.error('Error in /api/affiliate/mark-notification:', error.message);
    res.status(500).json({ success: false, message: 'Failed to mark notification', error: error.message });
  }
});

app.post('/api/affiliate/delete-account', authenticateAffiliate, async (req, res) => {
  try {
    const affiliates = await fetchAffiliates();
    const affiliate = affiliates.find(a => a.Email === req.user.email);
    if (!affiliate) {
      return res.status(401).json({ success: false, message: 'Affiliate not found' });
    }
    if (affiliate.CurrentBalance >= 1 || affiliate.WithdrawalsJSON.some(w => w.status === 'Pending')) {
      return res.status(400).json({ success: false, message: 'Withdraw all money before deleting account' });
    }
    affiliate.Statusjson = { status: 'deleted' };
    await updateAffiliateField(affiliate.Email, 'Statusjson', affiliate.Statusjson);
    await logTransaction(affiliate.Email, 'delete_account', {});
    await sendEmail(
      affiliate.Email,
      'Account Deleted',
      `Your affiliate account has been deleted. Contact ${cachedDataAffiliate.settings.supportEmail} for any questions.`
    );
    if (wsClients.has(affiliate.Email)) {
      wsClients.get(affiliate.Email).send(JSON.stringify({
        type: 'logout',
        message: 'Account deleted, please re-login'
      }));
      wsClients.delete(affiliate.Email);
    }
    res.json({ success: true, message: 'Account deleted successfully' });
  } catch (error) {
    console.error('Error in /api/affiliate/delete-account:', error.message);
    res.status(500).json({ success: false, message: 'Failed to delete account', error: error.message });
  }
});

app.get('/api/affiliate/validate', authenticateAffiliate, async (req, res) => {
  try {
    const affiliate = cachedDataAffiliate.affiliates.find(a => a.Email === req.user.email);
    if (!affiliate || affiliate.Statusjson.status !== 'active') {
      return res.status(401).json({ success: false, message: 'Invalid or inactive session' });
    }
    res.json({ success: true, data: { email: affiliate.Email, username: affiliate.Username, name: affiliate.Name } });
  } catch (error) {
    console.error('Error in /api/affiliate/validate:', error.message);
    res.status(401).json({ success: false, message: 'Session validation failed', error: error.message });
  }
});

app.get('/api/admin/affiliate/validate', authenticateAdmin, async (req, res) => {
  try {
    const settings = await fetchSettings();
    if (req.user.email !== settings.adminEmail) {
      return res.status(401).json({ success: false, message: 'Invalid admin session' });
    }
    res.json({ success: true, data: { email: settings.adminEmail } });
  } catch (error) {
    console.error('Error in /api/admin/affiliate/validate:', error.message);
    res.status(401).json({ success: false, message: 'Admin session validation failed', error: error.message });
  }
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.stack);
  res.status(500).json({ success: false, message: 'Server error, please try again later' });
});

// Start Server
const server = app.listen(port, async () => {
  try {
    await initializeSheets();
    await updateCache();
    console.log(`Server running on port ${port}`);
  } catch (err) {
    console.error('Failed to start server:', err.message);
    process.exit(1);
  }
});

// WebSocket Upgrade
server.on('upgrade', (request, socket, head) => {
  const url = new URL(request.url, `http://${request.headers.host}`);
  const token = url.searchParams.get('token');
  const decoded = validateWebSocket(token);
  if (!decoded) {
    socket.write('Invalid token');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request, decoded);
  });
});

// Graceful Shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down');
  wsClients.forEach(ws => ws.terminate());
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});
