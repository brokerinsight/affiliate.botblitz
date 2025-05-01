const express = require('express');
const { google } = require('googleapis');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const { Server } = require('socket.io');
const http = require('http');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: 'https://affiliate-botblitz.onrender.com',
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

app.use(cors({ origin: 'https://affiliate-botblitz.onrender.com', credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true, sameSite: 'strict' },
}));

// Rate limiter for login endpoints
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5,
  keyGenerator: (req) => req.ip,
  handler: (req, res) => {
    res.status(429).json({ error: 'Too many login attempts', attemptsLeft: 0 });
  },
});

// Google Sheets setup
const sheets = google.sheets({ version: 'v4' });
const auth = new google.auth.GoogleAuth({
  keyFile: './google-credentials.json',
  scopes: ['https://www.googleapis.com/auth/spreadsheets'],
});

const ADMIN_SHEET_ID = process.env.ADMIN_SHEET_ID;
const AFFILIATES_SHEET_ID = process.env.AFFILIATES_SHEET_ID;
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret';

// Cache for affiliate data
let cachedDataAffiliate = {
  affiliates: [],
  settings: {},
  staticPages: [],
  pendingWithdrawals: [],
  sortedWithdrawals: [],
  leaderboard: [],
};

// Email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Initialize Google Sheets tabs
async function initializeSheets() {
  const client = await auth.getClient();
  const adminTabs = [
    'settingsAffiliate',
    'staticPagesAffiliate',
    'blocklist',
    'deletedEmails',
    'allActiveAffiliates',
    'leaderboard',
    'pendingWithdrawals',
    'sortedWithdrawals',
  ];

  for (const tab of adminTabs) {
    try {
      await sheets.spreadsheets.get({
        auth: client,
        spreadsheetId: ADMIN_SHEET_ID,
        ranges: [tab],
      });
    } catch (err) {
      await sheets.spreadsheets.batchUpdate({
        auth: client,
        spreadsheetId: ADMIN_SHEET_ID,
        resource: {
          requests: [{ addSheet: { properties: { title: tab } } }],
        },
      });
    }
  }

  // Initialize default settings
  const defaultSettings = [
    ['supportEmail', 'derivbotstore@gmail.com'],
    ['whatsappLink', 'https://wa.link/4wppln'],
    ['copyrightText', 'Deriv Bot Store Affiliates 2025'],
    ['adminEmail', 'martinke444@gmail.com'],
    ['adminPassword', await bcrypt.hash('kaylie2025', 10)],
    ['commissionRate', '0.2'],
    ['urgentPopup', JSON.stringify({ message: '', enabled: false })],
  ];

  const settings = await sheets.spreadsheets.values.get({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'settingsAffiliate!A2:B',
  });

  if (!settings.data.values || settings.data.values.length === 0) {
    await sheets.spreadsheets.values.update({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'settingsAffiliate!A2:B',
      valueInputOption: 'RAW',
      resource: { values: defaultSettings },
    });
  }
}

// Load cached data
async function loadCachedData() {
  const client = await auth.getClient();
  const [affiliates, settings, staticPages, pendingWithdrawals, sortedWithdrawals, leaderboard] = await Promise.all([
    sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'allActiveAffiliates!A2:G',
    }),
    sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'settingsAffiliate!A2:B',
    }),
    sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'staticPagesAffiliate!A2:C',
    }),
    sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'pendingWithdrawals!A2:E',
    }),
    sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'sortedWithdrawals!A2:G',
    }),
    sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'leaderboard!A2:F',
    }),
  ]);

  cachedDataAffiliate.affiliates = affiliates.data.values?.map(row => ({
    email: row[0],
    name: row[1],
    joinDate: row[2],
    linkClicks: parseInt(row[3] || '0'),
    saleCount: parseInt(row[4] || '0'),
    totalEarnings: parseFloat(row[5] || '0'),
    withdrawnTotal: parseFloat(row[6] || '0'),
  })) || [];

  cachedDataAffiliate.settings = settings.data.values?.reduce((acc, [key, value]) => ({
    ...acc,
    [key]: key === 'urgentPopup' ? JSON.parse(value || '{}') : key === 'commissionRate' ? parseFloat(value) : value,
  }), {}) || {};

  cachedDataAffiliate.staticPages = staticPages.data.values?.map(row => ({
    slug: row[0],
    title: row[1],
    content: row[2],
  })) || [];

  cachedDataAffiliate.pendingWithdrawals = pendingWithdrawals.data.values?.map(row => ({
    email: row[0],
    timestamp: row[1],
    amount: parseFloat(row[2]),
    mpesaNumber: row[3],
    mpesaName: row[4],
  })) || [];

  cachedDataAffiliate.sortedWithdrawals = sortedWithdrawals.data.values?.map(row => ({
    email: row[0],
    timestamp: row[1],
    amount: parseFloat(row[2]),
    mpesaNumber: row[3],
    mpesaName: row[4],
    status: row[5],
    mpesaRef: row[6],
  })) || [];

  cachedDataAffiliate.leaderboard = leaderboard.data.values?.map(row => ({
    rewardId: row[0],
    affiliateName: row[1],
    rewardType: row[2],
    rewardValue: parseFloat(row[3]),
    endDate: row[4],
    ongoing: row[5] === 'true',
  })) || [];

  io.emit('update', cachedDataAffiliate);
}

// Cron refresh every 15 minutes
setInterval(loadCachedData, 15 * 60 * 1000);

// Middleware to verify JWT
function authenticateToken(req, res, next) {
  const token = req.cookies.jwt;
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Serve static pages
app.get('/affiliate-:slug', async (req, res) => {
  const { slug } = req.params;
  const page = cachedDataAffiliate.staticPages.find(p => p.slug === `/affiliate-${slug}`);
  if (!page) return res.status(404).send('Page not found');
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${page.title}</title>
      <link href="/output.css" rel="stylesheet">
    </head>
    <body class="bg-gray-100 dark:bg-gray-900 min-h-screen">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        ${page.content}
      </div>
    </body>
    </html>
  `);
});

// AUTH ENDPOINTS
app.post('/api/affiliate/register', async (req, res) => {
  const { name, email, password, terms } = req.body;
  if (!name || !email || !password || !terms) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (!/^[a-zA-Z\s]+$/.test(name)) {
    return res.status(400).json({ error: 'Name must contain only letters and spaces' });
  }
  if (!/\S+@\S+\.\S+/.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  if (password.length < 8 || !/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
    return res.status(400).json({ error: 'Password must be 8+ characters with letters and numbers' });
  }

  const client = await auth.getClient();
  const [blocklist, deletedEmails, affiliates] = await Promise.all([
    sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'blocklist!A2:A',
    }),
    sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'deletedEmails!A2:A',
    }),
    sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'allActiveAffiliates!A2:A',
    }),
  ]);

  if (blocklist.data.values?.some(row => row[0] === email) || deletedEmails.data.values?.some(row => row[0] === email)) {
    return res.status(403).json({ error: 'Account blocked or deleted' });
  }
  if (affiliates.data.values?.some(row => row[0] === email)) {
    return res.status(400).json({ error: 'Email already registered' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const refCode = uuidv4().slice(0, 8);
  const joinDate = new Date().toISOString();

  await sheets.spreadsheets.batchUpdate({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    resource: {
      requests: [{
        addSheet: {
          properties: { title: email },
        },
      }],
    },
  });

  const tabs = ['Details', 'Withdrawals', 'Rewards', 'Notifications'];
  for (const tab of tabs) {
    await sheets.spreadsheets.values.update({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${email}!${tab}!A1`,
      valueInputOption: 'RAW',
      resource: {
        values: [tab === 'Details' ? ['Email', 'Name', 'RefCode', 'HashedPassword', 'LinkClicks', 'SaleCount', 'CurrentBalance', 'TotalEarnings', 'WithdrawnTotal', 'Status']
                : tab === 'Withdrawals' ? ['Timestamp', 'Amount', 'MpesaNumber', 'MpesaName', 'Status', 'MpesaRef']
                : tab === 'Rewards' ? ['Timestamp', 'RewardType', 'RewardValue', 'Duration', 'EndDate']
                : ['Timestamp', 'Message', 'Read']],
      },
    });
  }

  await sheets.spreadsheets.values.append({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${email}!Details!A2`,
    valueInputOption: 'RAW',
    resource: {
      values: [[email, name, refCode, hashedPassword, 0, 0, 0, 0, 0, 'active']],
    },
  });

  await sheets.spreadsheets.values.append({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'allActiveAffiliates!A2',
    valueInputOption: 'RAW',
    resource: {
      values: [[email, name, joinDate, 0, 0, 0, 0]],
    },
  });

  cachedDataAffiliate.affiliates.push({ email, name, joinDate, linkClicks: 0, saleCount: 0, totalEarnings: 0, withdrawnTotal: 0 });
  io.emit('update', cachedDataAffiliate);

  const token = jwt.sign({ email, role: 'affiliate' }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, refCode, name });
});

app.post('/api/affiliate/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const client = await auth.getClient();
  const [blocklist, deletedEmails, affiliate] = await Promise.all([
    sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'blocklist!A2:A',
    }),
    sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'deletedEmails!A2:A',
    }),
    sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${email}!Details!A2:J`,
    }),
  ]);

  if (blocklist.data.values?.some(row => row[0] === email) || deletedEmails.data.values?.some(row => row[0] === email)) {
    return res.status(403).json({ error: 'Account blocked or deleted', attemptsLeft: 5 });
  }
  if (!affiliate.data.values || affiliate.data.values.length === 0) {
    return res.status(401).json({ error: 'Invalid credentials', attemptsLeft: req.rateLimit.remaining || 4 });
  }

  const [_, name, refCode, hashedPassword, linkClicks, saleCount, currentBalance, totalEarnings, withdrawnTotal, status] = affiliate.data.values[0];
  if (status === 'blocked') {
    return res.status(403).json({ error: 'Account blocked', attemptsLeft: 5 });
  }

  const isValid = await bcrypt.compare(password, hashedPassword);
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid credentials', attemptsLeft: req.rateLimit.remaining || 4 });
  }

  const token = jwt.sign({ email, role: 'affiliate' }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, refCode, name });
});

app.post('/api/admin/affiliate/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const client = await auth.getClient();
  const settings = await sheets.spreadsheets.values.get({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'settingsAffiliate!A2:B',
  });

  const adminEmail = settings.data.values?.find(row => row[0] === 'adminEmail')?.[1];
  const adminPassword = settings.data.values?.find(row => row[0] === 'adminPassword')?.[1];

  if (email !== adminEmail) {
    return res.status(401).json({ error: 'Invalid credentials', attemptsLeft: req.rateLimit.remaining || 4 });
  }

  const isValid = await bcrypt.compare(password, adminPassword);
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid credentials', attemptsLeft: req.rateLimit.remaining || 4 });
  }

  const token = jwt.sign({ email, role: 'admin' }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

app.get('/api/admin/affiliate/verify', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  res.json({ valid: true });
});

// DASHBOARD DATA ENDPOINTS
app.get('/api/affiliate/data', authenticateToken, async (req, res) => {
  const { email } = req.user;
  const client = await auth.getClient();
  const [details, withdrawals, rewards, notifications] = await Promise.all([
    sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${email}!Details!A2:J`,
    }),
    sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${email}!Withdrawals!A2:F`,
    }),
    sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${email}!Rewards!A2:E`,
    }),
    sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${email}!Notifications!A2:C`,
    }),
  ]);

  const leaderboard = cachedDataAffiliate.affiliates
    .sort((a, b) => b.saleCount - a.saleCount)
    .slice(0, 10)
    .map(a => ({ name: a.name, saleCount: a.saleCount }));

  res.json({
    name: details.data.values?.[0]?.[1] || '',
    refCode: details.data.values?.[0]?.[2] || '',
    linkClicks: parseInt(details.data.values?.[0]?.[4] || '0'),
    saleCount: parseInt(details.data.values?.[0]?.[5] || '0'),
    currentBalance: parseFloat(details.data.values?.[0]?.[6] || '0'),
    totalEarnings: parseFloat(details.data.values?.[0]?.[7] || '0'),
    withdrawals: withdrawals.data.values?.slice(-20).map(row => ({
      timestamp: row[0],
      amount: parseFloat(row[1]),
      mpesaNumber: row[2],
      mpesaName: row[3],
      status: row[4],
      mpesaRef: row[5],
    })) || [],
    rewards: rewards.data.values?.map(row => ({
      timestamp: row[0],
      rewardType: row[1],
      rewardValue: parseFloat(row[2]),
      duration: parseInt(row[3]),
      endDate: row[4],
    })) || [],
    notifications: notifications.data.values?.map(row => ({
      timestamp: row[0],
      message: row[1],
      read: row[2] === 'true',
    })) || [],
    leaderboard,
  });
});

app.get('/api/admin/affiliate/data', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  res.json(cachedDataAffiliate);
});

app.get('/api/admin/affiliate/affiliates', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  res.json(cachedDataAffiliate.affiliates);
});

app.get('/api/admin/affiliate/withdrawals', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  res.json(cachedDataAffiliate.pendingWithdrawals);
});

app.get('/api/admin/affiliate/sorted-withdrawals', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  res.json(cachedDataAffiliate.sortedWithdrawals);
});

app.get('/api/admin/affiliate/staticpages', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  res.json(cachedDataAffiliate.staticPages);
});

// TRACKING ENDPOINTS
app.post('/api/affiliate/track-click', async (req, res) => {
  const { refCode } = req.body;
  if (!refCode) {
    return res.status(400).json({ error: 'RefCode required' });
  }

  const affiliate = cachedDataAffiliate.affiliates.find(a => a.refCode === refCode);
  if (!affiliate) {
    return res.status(404).json({ error: 'Affiliate not found' });
  }

  const client = await auth.getClient();
  const details = await sheets.spreadsheets.values.get({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${affiliate.email}!Details!A2:J`,
  });

  if (!details.data.values) {
    return res.status(404).json({ error: 'Affiliate data not found' });
  }

  const row = details.data.values[0];
  row[4] = parseInt(row[4] || '0') + 1; // Increment LinkClicks

  await sheets.spreadsheets.values.update({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${affiliate.email}!Details!A2:J`,
    valueInputOption: 'RAW',
    resource: { values: [row] },
  });

  const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.email === affiliate.email);
  cachedDataAffiliate.affiliates[affiliateIndex].linkClicks = row[4];
  io.emit('update', cachedDataAffiliate);

  res.json({ success: true });
});

app.post('/api/affiliate/confirmed-sale', async (req, res) => {
  const { refCode, amount, item } = req.body;
  if (!refCode || !amount || !item) {
    return res.status(400).json({ error: 'RefCode, amount, and item required' });
  }

  const affiliate = cachedDataAffiliate.affiliates.find(a => a.refCode === refCode);
  if (!affiliate) {
    return res.status(404).json({ error: 'Affiliate not found' });
  }

  const commissionRate = cachedDataAffiliate.settings.commissionRate || 0.2;
  const commission = amount * commissionRate;

  const client = await auth.getClient();
  const details = await sheets.spreadsheets.values.get({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${affiliate.email}!Details!A2:J`,
  });

  if (!details.data.values) {
    return res.status(404).json({ error: 'Affiliate data not found' });
  }

  const row = details.data.values[0];
  row[5] = parseInt(row[5] || '0') + 1; // Increment SaleCount
  row[6] = parseFloat(row[6] || '0') + commission; // Increment CurrentBalance
  row[7] = parseFloat(row[7] || '0') + commission; // Increment TotalEarnings

  await sheets.spreadsheets.values.update({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${affiliate.email}!Details!A2:J`,
    valueInputOption: 'RAW',
    resource: { values: [row] },
  });

  const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.email === affiliate.email);
  cachedDataAffiliate.affiliates[affiliateIndex].saleCount = row[5];
  cachedDataAffiliate.affiliates[affiliateIndex].totalEarnings = row[7];
  io.emit('update', cachedDataAffiliate);

  // Handle referrer bonus (5% of commission)
  if (affiliate.referrerEmail) {
    const referrerDetails = await sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${affiliate.referrerEmail}!Details!A2:J`,
    });

    if (referrerDetails.data.values) {
      const referrerRow = referrerDetails.data.values[0];
      const bonus = commission * 0.05;
      referrerRow[6] = parseFloat(referrerRow[6] || '0') + bonus;
      referrerRow[7] = parseFloat(referrerRow[7] || '0') + bonus;

      await sheets.spreadsheets.values.update({
        auth: client,
        spreadsheetId: AFFILIATES_SHEET_ID,
        range: `${affiliate.referrerEmail}!Details!A2:J`,
        valueInputOption: 'RAW',
        resource: { values: [referrerRow] },
      });

      await sheets.spreadsheets.values.append({
        auth: client,
        spreadsheetId: AFFILIATES_SHEET_ID,
        range: `${affiliate.referrerEmail}!Rewards!A2`,
        valueInputOption: 'RAW',
        resource: {
          values: [[new Date().toISOString(), 'referral_bonus', bonus, 0, '']],
        },
      });

      const referrerIndex = cachedDataAffiliate.affiliates.findIndex(a => a.email === affiliate.referrerEmail);
      if (referrerIndex !== -1) {
        cachedDataAffiliate.affiliates[referrerIndex].totalEarnings = referrerRow[7];
      }
      io.emit('update', cachedDataAffiliate);
    }
  }

  res.json({ success: true });
});

// WITHDRAWAL ENDPOINTS
app.post('/api/affiliate/request-withdrawal', authenticateToken, async (req, res) => {
  const { amount, mpesaNumber, mpesaName, reuse, password } = req.body;
  const { email } = req.user;

  if (!amount || !mpesaNumber || !mpesaName || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (amount <= 0) {
    return res.status(400).json({ error: 'Amount must be positive' });
  }
  if (!/^\+254\d{9}$/.test(mpesaNumber)) {
    return res.status(400).json({ error: 'Invalid Mpesa number' });
  }

  const client = await auth.getClient();
  const details = await sheets.spreadsheets.values.get({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${email}!Details!A2:J`,
  });

  if (!details.data.values) {
    return res.status(404).json({ error: 'Affiliate not found' });
  }

  const [_, __, ___, hashedPassword, ____, _____, currentBalance] = details.data.values[0];
  const isValid = await bcrypt.compare(password, hashedPassword);
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid password' });
  }

  if (parseFloat(currentBalance) < amount) {
    return res.status(400).json({ error: 'Insufficient balance' });
  }

  const timestamp = new Date().toISOString();
  details.data.values[0][6] = parseFloat(currentBalance) - amount; // Deduct from CurrentBalance

  await sheets.spreadsheets.values.update({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${email}!Details!A2:J`,
    valueInputOption: 'RAW',
    resource: { values: details.data.values },
  });

  await sheets.spreadsheets.values.append({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${email}!Withdrawals!A2`,
    valueInputOption: 'RAW',
    resource: {
      values: [[timestamp, amount, mpesaNumber, mpesaName, 'pending', '']],
    },
  });

  await sheets.spreadsheets.values.append({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'pendingWithdrawals!A2',
    valueInputOption: 'RAW',
    resource: {
      values: [[email, timestamp, amount, mpesaNumber, mpesaName]],
    },
  });

  cachedDataAffiliate.pendingWithdrawals.push({ email, timestamp, amount, mpesaNumber, mpesaName });
  io.emit('update', cachedDataAffiliate);

  // Send email notification to admin
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: cachedDataAffiliate.settings.adminEmail,
    subject: 'New Withdrawal Request',
    text: `Affiliate ${email} requested a withdrawal of KES ${amount} to Mpesa ${mpesaNumber} (${mpesaName}).`,
  });

  res.json({ success: true });
});

app.post('/api/admin/affiliate/withdrawals/confirm', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const { email, timestamp, amount, mpesaNumber, mpesaName, mpesaRef } = req.body;
  if (!email || !timestamp || !amount || !mpesaNumber || !mpesaName || !mpesaRef) {
    return res.status(400).json({ error: 'All fields required' });
  }

  const client = await auth.getClient();
  await sheets.spreadsheets.values.append({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'sortedWithdrawals!A2',
    valueInputOption: 'RAW',
    resource: {
      values: [[email, timestamp, amount, mpesaNumber, mpesaName, 'done', mpesaRef]],
    },
  });

  await sheets.spreadsheets.values.update({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${email}!Withdrawals!A2:F`,
    valueInputOption: 'RAW',
    resource: {
      values: (await sheets.spreadsheets.values.get({
        auth: client,
        spreadsheetId: AFFILIATES_SHEET_ID,
        range: `${email}!Withdrawals!A2:F`,
      })).data.values.map(row => 
        row[0] === timestamp ? [timestamp, amount, mpesaNumber, mpesaName, 'done', mpesaRef] : row
      ),
    },
  });

  const pending = await sheets.spreadsheets.values.get({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'pendingWithdrawals!A2:E',
  });

  await sheets.spreadsheets.values.update({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'pendingWithdrawals!A2:E',
    valueInputOption: 'RAW',
    resource: {
      values: pending.data.values?.filter(row => !(row[0] === email && row[1] === timestamp)) || [],
    },
  });

  const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.email === email);
  if (affiliateIndex !== -1) {
    cachedDataAffiliate.affiliates[affiliateIndex].withdrawnTotal += amount;
  }
  cachedDataAffiliate.pendingWithdrawals = cachedDataAffiliate.pendingWithdrawals.filter(w => !(w.email === email && w.timestamp === timestamp));
  cachedDataAffiliate.sortedWithdrawals.push({ email, timestamp, amount, mpesaNumber, mpesaName, status: 'done', mpesaRef });
  io.emit('update', cachedDataAffiliate);

  await sheets.spreadsheets.values.append({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${email}!Notifications!A2`,
    valueInputOption: 'RAW',
    resource: {
      values: [[new Date().toISOString(), `Withdrawal of KES ${amount} confirmed. Mpesa Ref: ${mpesaRef}`, 'false']],
    },
  });

  res.json({ success: true });
});

app.post('/api/admin/affiliate/withdrawals/dispute', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const { email, timestamp, amount, mpesaNumber, mpesaName } = req.body;
  if (!email || !timestamp || !amount || !mpesaNumber || !mpesaName) {
    return res.status(400).json({ error: 'All fields required' });
  }

  const client = await auth.getClient();
  const details = await sheets.spreadsheets.values.get({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${email}!Details!A2:J`,
  });

  if (!details.data.values) {
    return res.status(404).json({ error: 'Affiliate not found' });
  }

  details.data.values[0][6] = parseFloat(details.data.values[0][6] || '0') + amount; // Refund CurrentBalance

  await sheets.spreadsheets.values.update({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${email}!Details!A2:J`,
    valueInputOption: 'RAW',
    resource: { values: details.data.values },
  });

  await sheets.spreadsheets.values.append({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'sortedWithdrawals!A2',
    valueInputOption: 'RAW',
    resource: {
      values: [[email, timestamp, amount, mpesaNumber, mpesaName, 'disputed', '']],
    },
  });

  await sheets.spreadsheets.values.update({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${email}!Withdrawals!A2:F`,
    valueInputOption: 'RAW',
    resource: {
      values: (await sheets.spreadsheets.values.get({
        auth: client,
        spreadsheetId: AFFILIATES_SHEET_ID,
        range: `${email}!Withdrawals!A2:F`,
      })).data.values.map(row => 
        row[0] === timestamp ? [timestamp, amount, mpesaNumber, mpesaName, 'disputed', ''] : row
      ),
    },
  });

  const pending = await sheets.spreadsheets.values.get({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'pendingWithdrawals!A2:E',
  });

  await sheets.spreadsheets.values.update({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'pendingWithdrawals!A2:E',
    valueInputOption: 'RAW',
    resource: {
      values: pending.data.values?.filter(row => !(row[0] === email && row[1] === timestamp)) || [],
    },
  });

  cachedDataAffiliate.pendingWithdrawals = cachedDataAffiliate.pendingWithdrawals.filter(w => !(w.email === email && w.timestamp === timestamp));
  cachedDataAffiliate.sortedWithdrawals.push({ email, timestamp, amount, mpesaNumber, mpesaName, status: 'disputed', mpesaRef: '' });
  io.emit('update', cachedDataAffiliate);

  await sheets.spreadsheets.values.append({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${email}!Notifications!A2`,
    valueInputOption: 'RAW',
    resource: {
      values: [[new Date().toISOString(), `Withdrawal of KES ${amount} disputed and refunded.`, 'false']],
    },
  });

  res.json({ success: true });
});

// REWARD ENDPOINTS
app.post('/api/admin/affiliate/rewards', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const { type, topN, threshold, rewardType, rewardValue, duration } = req.body;
  if (!type || !rewardType || !rewardValue || !duration) {
    return res.status(400).json({ error: 'All fields required' });
  }
  if (type === 'leaderboard' && !topN) {
    return res.status(400).json({ error: 'Top N required for leaderboard rewards' });
  }
  if (type === 'sale' && !threshold) {
    return res.status(400).json({ error: 'Threshold required for sale rewards' });
  }

  const client = await auth.getClient();
  const endDate = new Date(Date.now() + duration * 24 * 60 * 60 * 1000).toISOString();
  const rewardId = uuidv4();

  let eligibleAffiliates = [];
  if (type === 'leaderboard') {
    eligibleAffiliates = cachedDataAffiliate.affiliates
      .sort((a, b) => b.saleCount - a.saleCount)
      .slice(0, topN);
  } else {
    eligibleAffiliates = cachedDataAffiliate.affiliates.filter(a => a.saleCount >= threshold);
  }

  for (const affiliate of eligibleAffiliates) {
    const details = await sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${affiliate.email}!Details!A2:J`,
    });

    if (!details.data.values) continue;

    const row = details.data.values[0];
    let amount = 0;
    if (rewardType === 'fixed') {
      amount = parseFloat(rewardValue);
    } else if (rewardType === 'percentage') {
      amount = parseFloat(row[7] || '0') * (parseFloat(rewardValue) / 100);
    } else if (rewardType === 'commission') {
      amount = parseFloat(rewardValue) / 100; // Commission rate increase
    }

    if (rewardType !== 'commission') {
      row[6] = parseFloat(row[6] || '0') + amount; // Add to CurrentBalance
      row[7] = parseFloat(row[7] || '0') + amount; // Add to TotalEarnings
    }

    await sheets.spreadsheets.values.update({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${affiliate.email}!Details!A2:J`,
      valueInputOption: 'RAW',
      resource: { values: [row] },
    });

    await sheets.spreadsheets.values.append({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${affiliate.email}!Rewards!A2`,
      valueInputOption: 'RAW',
      resource: {
        values: [[new Date().toISOString(), rewardType, rewardValue, duration, endDate]],
      },
    });

    await sheets.spreadsheets.values.append({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'leaderboard!A2',
      valueInputOption: 'RAW',
      resource: {
        values: [[rewardId, affiliate.name, rewardType, rewardValue, endDate, 'true']],
      },
    });

    const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.email === affiliate.email);
    if (affiliateIndex !== -1 && rewardType !== 'commission') {
      cachedDataAffiliate.affiliates[affiliateIndex].totalEarnings = row[7];
    }
    cachedDataAffiliate.leaderboard.push({ rewardId, affiliateName: affiliate.name, rewardType, rewardValue, endDate, ongoing: true });
  }

  io.emit('update', cachedDataAffiliate);
  res.json({ success: true });
});

app.post('/api/admin/affiliate/rewards/terminate', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const { rewardId } = req.body;
  if (!rewardId) {
    return res.status(400).json({ error: 'Reward ID required' });
  }

  const client = await auth.getClient();
  const leaderboard = await sheets.spreadsheets.values.get({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'leaderboard!A2:F',
  });

  if (!leaderboard.data.values) {
    return res.status(404).json({ error: 'Reward not found' });
  }

  const updatedLeaderboard = leaderboard.data.values.map(row => 
    row[0] === rewardId ? [...row.slice(0, 5), 'false'] : row
  );

  await sheets.spreadsheets.values.update({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'leaderboard!A2:F',
    valueInputOption: 'RAW',
    resource: { values: updatedLeaderboard },
  });

  cachedDataAffiliate.leaderboard = cachedDataAffiliate.leaderboard.map(r => 
    r.rewardId === rewardId ? { ...r, ongoing: false } : r
  );
  io.emit('update', cachedDataAffiliate);

  res.json({ success: true });
});

// STATIC PAGES ENDPOINTS
app.post('/api/admin/affiliate/staticpages', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const { action, title, content, slug } = req.body;
  if (!action || (action !== 'delete' && (!title || !content))) {
    return res.status(400).json({ error: 'Action and fields required' });
  }

  const client = await auth.getClient();
  if (action === 'create') {
    const newSlug = `/affiliate-${title.toLowerCase().replace(/\s+/g, '-')}`;
    await sheets.spreadsheets.values.append({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'staticPagesAffiliate!A2',
      valueInputOption: 'RAW',
      resource: {
        values: [[newSlug, title, content]],
      },
    });
    cachedDataAffiliate.staticPages.push({ slug: newSlug, title, content });
  } else if (action === 'edit') {
    const pages = await sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'staticPagesAffiliate!A2:C',
    });

    const updatedPages = pages.data.values?.map(row => 
      row[0] === slug ? [slug, title, content] : row
    ) || [];

    await sheets.spreadsheets.values.update({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'staticPagesAffiliate!A2:C',
      valueInputOption: 'RAW',
      resource: { values: updatedPages },
    });

    const pageIndex = cachedDataAffiliate.staticPages.findIndex(p => p.slug === slug);
    if (pageIndex !== -1) {
      cachedDataAffiliate.staticPages[pageIndex] = { slug, title, content };
    }
  } else if (action === 'delete') {
    const pages = await sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'staticPagesAffiliate!A2:C',
    });

    const updatedPages = pages.data.values?.filter(row => row[0] !== slug) || [];

    await sheets.spreadsheets.values.update({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'staticPagesAffiliate!A2:C',
      valueInputOption: 'RAW',
      resource: { values: updatedPages },
    });

    cachedDataAffiliate.staticPages = cachedDataAffiliate.staticPages.filter(p => p.slug !== slug);
  }

  io.emit('update', cachedDataAffiliate);
  res.json({ success: true });
});

// COMMUNICATION ENDPOINTS
app.post('/api/admin/affiliate/communication', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const { type, message, enabled, filter, saleCount } = req.body;
  if (!type || (type === 'notification' && !message) || (type === 'popup' && enabled && !message)) {
    return res.status(400).json({ error: 'Required fields missing' });
  }

  const client = await auth.getClient();
  if (type === 'popup') {
    cachedDataAffiliate.settings.urgentPopup = { message: message || '', enabled: !!enabled };
    await sheets.spreadsheets.values.update({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'settingsAffiliate!A2:B',
      valueInputOption: 'RAW',
      resource: {
        values: Object.entries(cachedDataAffiliate.settings).map(([key, value]) => 
          [key, key === 'urgentPopup' ? JSON.stringify(value) : value]
        ),
      },
    });
  } else if (type === 'notification') {
    let eligibleAffiliates = cachedDataAffiliate.affiliates;
    if (filter === 'saleCount') {
      if (!saleCount) {
        return res.status(400).json({ error: 'Sale count required' });
      }
      eligibleAffiliates = eligibleAffiliates.filter(a => a.saleCount < parseInt(saleCount));
    }

    for (const affiliate of eligibleAffiliates) {
      await sheets.spreadsheets.values.append({
        auth: client,
        spreadsheetId: AFFILIATES_SHEET_ID,
        range: `${affiliate.email}!Notifications!A2`,
        valueInputOption: 'RAW',
        resource: {
          values: [[new Date().toISOString(), message, 'false']],
        },
      });
    }
  }

  io.emit('update', cachedDataAffiliate);
  res.json({ success: true });
});

// SETTINGS ENDPOINTS
app.post('/api/admin/affiliate/settings', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const { supportEmail, whatsappLink, copyrightText, adminEmail, adminPassword, commissionRate } = req.body;
  const updates = {};

  if (supportEmail) updates.supportEmail = supportEmail;
  if (whatsappLink) updates.whatsappLink = whatsappLink;
  if (copyrightText) updates.copyrightText = copyrightText;
  if (adminEmail) updates.adminEmail = adminEmail;
  if (adminPassword) {
    if (adminPassword.length < 8 || !/[a-zA-Z]/.test(adminPassword) || !/[0-9]/.test(adminPassword)) {
      return res.status(400).json({ error: 'Password must be 8+ characters with letters and numbers' });
    }
    updates.adminPassword = await bcrypt.hash(adminPassword, 10);
  }
  if (commissionRate) {
    if (commissionRate <= 0 || commissionRate > 1) {
      return res.status(400).json({ error: 'Commission rate must be between 0 and 1' });
    }
    updates.commissionRate = commissionRate;
  }

  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ error: 'No valid fields provided' });
  }

  const client = await auth.getClient();
  cachedDataAffiliate.settings = { ...cachedDataAffiliate.settings, ...updates };

  await sheets.spreadsheets.values.update({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'settingsAffiliate!A2:B',
    valueInputOption: 'RAW',
    resource: {
      values: Object.entries(cachedDataAffiliate.settings).map(([key, value]) => 
        [key, key === 'urgentPopup' ? JSON.stringify(value) : value]
      ),
    },
  });

  io.emit('update', cachedDataAffiliate);
  res.json({ success: true });
});

app.post('/api/affiliate/update-password', authenticateToken, async (req, res) => {
  const { email } = req.user;
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new passwords required' });
  }
  if (newPassword.length < 8 || !/[a-zA-Z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
    return res.status(400).json({ error: 'New password must be 8+ characters with letters and numbers' });
  }

  const client = await auth.getClient();
  const details = await sheets.spreadsheets.values.get({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${email}!Details!A2:J`,
  });

  if (!details.data.values) {
    return res.status(404).json({ error: 'Affiliate not found' });
  }

  const isValid = await bcrypt.compare(currentPassword, details.data.values[0][3]);
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid current password' });
  }

  details.data.values[0][3] = await bcrypt.hash(newPassword, 10);

  await sheets.spreadsheets.values.update({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${email}!Details!A2:J`,
    valueInputOption: 'RAW',
    resource: { values: details.data.values },
  });

  io.emit('forceLogout', { email });
  res.json({ success: true });
});

app.post('/api/affiliate/delete-account', authenticateToken, async (req, res) => {
  const { email } = req.user;
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ error: 'Password required' });
  }

  const client = await auth.getClient();
  const details = await sheets.spreadsheets.values.get({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${email}!Details!A2:J`,
  });

  if (!details.data.values) {
    return res.status(404).json({ error: 'Affiliate not found' });
  }

  const isValid = await bcrypt.compare(password, details.data.values[0][3]);
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid password' });
  }

  const sheetsInfo = await sheets.spreadsheets.get({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
  });

  const sheet = sheetsInfo.data.sheets.find(s => s.properties.title === email);
  if (sheet) {
    await sheets.spreadsheets.batchUpdate({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      resource: {
        requests: [{
          deleteSheet: {
            sheetId: sheet.properties.sheetId,
          },
        }],
      },
    });
  }

  await sheets.spreadsheets.values.append({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'deletedEmails!A2',
    valueInputOption: 'RAW',
    resource: {
      values: [[email]],
    },
  });

  const affiliates = await sheets.spreadsheets.values.get({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'allActiveAffiliates!A2:G',
  });

  await sheets.spreadsheets.values.update({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'allActiveAffiliates!A2:G',
    valueInputOption: 'RAW',
    resource: {
      values: affiliates.data.values?.filter(row => row[0] !== email) || [],
    },
  });

  cachedDataAffiliate.affiliates = cachedDataAffiliate.affiliates.filter(a => a.email !== email);
  io.emit('update', cachedDataAffiliate);
  io.emit('forceLogout', { email });

  res.json({ success: true });
});

app.post('/api/admin/affiliate/block', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }

  const client = await auth.getClient();
  const details = await sheets.spreadsheets.values.get({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${email}!Details!A2:J`,
  });

  if (!details.data.values) {
    return res.status(404).json({ error: 'Affiliate not found' });
  }

  details.data.values[0][9] = 'blocked';

  await sheets.spreadsheets.values.update({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
    range: `${email}!Details!A2:J`,
    valueInputOption: 'RAW',
    resource: { values: details.data.values },
  });

  await sheets.spreadsheets.values.append({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'blocklist!A2',
    valueInputOption: 'RAW',
    resource: {
      values: [[email]],
    },
  });

  cachedDataAffiliate.affiliates = cachedDataAffiliate.affiliates.filter(a => a.email !== email);
  io.emit('update', cachedDataAffiliate);
  io.emit('forceLogout', { email });

  res.json({ success: true });
});

app.post('/api/admin/affiliate/delete', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }

  const client = await auth.getClient();
  const sheetsInfo = await sheets.spreadsheets.get({
    auth: client,
    spreadsheetId: AFFILIATES_SHEET_ID,
  });

  const sheet = sheetsInfo.data.sheets.find(s => s.properties.title === email);
  if (sheet) {
    await sheets.spreadsheets.batchUpdate({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      resource: {
        requests: [{
          deleteSheet: {
            sheetId: sheet.properties.sheetId,
          },
        }],
      },
    });
  }

  await sheets.spreadsheets.values.append({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'deletedEmails!A2',
    valueInputOption: 'RAW',
    resource: {
      values: [[email]],
    },
  });

  const affiliates = await sheets.spreadsheets.values.get({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'allActiveAffiliates!A2:G',
  });

  await sheets.spreadsheets.values.update({
    auth: client,
    spreadsheetId: ADMIN_SHEET_ID,
    range: 'allActiveAffiliates!A2:G',
    valueInputOption: 'RAW',
    resource: {
      values: affiliates.data.values?.filter(row => row[0] !== email) || [],
    },
  });

  cachedDataAffiliate.affiliates = cachedDataAffiliate.affiliates.filter(a => a.email !== email);
  io.emit('update', cachedDataAffiliate);
  io.emit('forceLogout', { email });

  res.json({ success: true });
});

// Initialize and start server
async function startServer() {
  await initializeSheets();
  await loadCachedData();
  server.listen(process.env.PORT || 3000, () => {
    console.log('Server running on port', process.env.PORT || 3000);
  });
}

startServer();
