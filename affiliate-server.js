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
const helmet = require('helmet');
const sanitizeHtml = require('sanitize-html');
const path = require('path');

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

// Middleware
app.use(helmet());
app.use(cors({ origin: 'https://affiliate-botblitz.onrender.com', credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true, sameSite: 'strict', maxAge: 24 * 60 * 60 * 1000 },
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
  credentials: {
    client_email: process.env.GOOGLE_CLIENT_EMAIL,
    private_key: process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  },
  scopes: ['https://www.googleapis.com/auth/spreadsheets'],
});

const ADMIN_SHEET_ID = process.env.ADMIN_SHEET_ID;
const AFFILIATES_SHEET_ID = process.env.AFFILIATES_SHEET_ID;
const JWT_SECRET = process.env.JWT_SECRET;
const AFFILIATE_API_KEY = process.env.AFFILIATE_API_KEY;

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
  try {
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
        range: 'allActiveAffiliates!A2:G',
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

    // Fetch refCodes and referrer for affiliates
    for (const affiliate of cachedDataAffiliate.affiliates) {
      const details = await sheets.spreadsheets.values.get({
        auth: client,
        spreadsheetId: AFFILIATES_SHEET_ID,
        range: `${affiliate.email}!Details!A2:K`,
      });
      affiliate.refCode = details.data.values?.[0]?.[2] || '';
      affiliate.referrerEmail = details.data.values?.[0]?.[10] || '';
    }

    cachedDataAffiliate.settings = settings.data.values?.reduce((acc, [key, value]) => ({
      ...acc,
      [key]: key === 'urgentPopup' ? JSON.parse(value || '{}') : key === 'commissionRate' ? parseFloat(value) : value,
    }), {}) || {};

    cachedDataAffiliate.staticPages = staticPages.data.values?.map(row => ({
      slug: row[0],
      title: row[1],
      content: sanitizeHtml(row[2], { allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img']) }),
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

    cachedDataAffiliate.leaderboard = affiliates.data.values
      ?.sort((a, b) => parseInt(b[4] || '0') - parseInt(a[4] || '0'))
      .slice(0, 10)
      .map(row => ({
        name: row[1],
        saleCount: parseInt(row[4] || '0'),
      })) || [];

    io.emit('update', cachedDataAffiliate);
  } catch (err) {
    console.error('Error loading cached data:', err);
  }
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

// Middleware to verify API key
function authenticateApiKey(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader !== `Bearer ${AFFILIATE_API_KEY}`) {
    return res.status(403).json({ error: 'Invalid API key' });
  }
  next();
}

// Serve frontend pages
app.get('/affiliate', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'affiliate.html'));
});

app.get('/admin/affiliate', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'virusaffiliate.html'));
});

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
    <body class="bg-gray-100 dark:bg-gray-900 min-h-screen text-gray-900 dark:text-gray-100">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        ${page.content}
        <button onclick="window.history.back()" class="mt-4 bg-blue-500 text-white p-2 rounded hover:bg-blue-600">Back</button>
      </div>
    </body>
    </html>
  `);
});

// Keep-alive ping endpoint
app.get('/api/ping', (req, res) => {
  res.json({ status: 'alive' });
});

// AUTH ENDPOINTS
app.post('/api/affiliate/register', async (req, res) => {
  const { name, email, password, terms, referrerCode } = req.body;
  if (!name || !email || !password || !terms) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (!/^[a-zA-Z\s]+$/.test(name) || name.split(' ').filter(Boolean).length < 2) {
    return res.status(400).json({ error: 'Full name must contain at least 2 words' });
  }
  if (!/\S+@\S+\.\S+/.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  if (password.length < 8 || !/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
    return res.status(400).json({ error: 'Password must be 8+ characters with letters and numbers' });
  }

  try {
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

    let referrerEmail = '';
    if (referrerCode) {
      const referrer = cachedDataAffiliate.affiliates.find(a => a.refCode === referrerCode);
      if (!referrer) {
        return res.status(400).json({ error: 'Invalid referrer code' });
      }
      referrerEmail = referrer.email;
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
          values: [tab === 'Details' ? ['Email', 'Name', 'RefCode', 'HashedPassword', 'LinkClicks', 'SaleCount', 'CurrentBalance', 'TotalEarnings', 'WithdrawnTotal', 'Status', 'ReferrerEmail']
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
        values: [[email, name, refCode, hashedPassword, 0, 0, 0, 0, 0, 'active', referrerEmail]],
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

    cachedDataAffiliate.affiliates.push({ email, name, joinDate, linkClicks: 0, saleCount: 0, totalEarnings: 0, withdrawnTotal: 0, refCode, referrerEmail });
    io.emit('update', cachedDataAffiliate);

    const token = jwt.sign({ email, role: 'affiliate' }, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('jwt', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 3600000 });
    res.json({ token, refCode, name });
  } catch (err) {
    console.error('Error in register:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/affiliate/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  try {
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
        range: `${email}!Details!A2:K`,
      }),
    ]);

    if (blocklist.data.values?.some(row => row[0] === email) || deletedEmails.data.values?.some(row => row[0] === email)) {
      return res.status(403).json({ error: 'Account blocked or deleted', attemptsLeft: req.rateLimit.remaining || 4 });
    }
    if (!affiliate.data.values || affiliate.data.values.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials', attemptsLeft: req.rateLimit.remaining || 4 });
    }

    const [_, name, refCode, hashedPassword, ___, ____, _____, ______, _______, status] = affiliate.data.values[0];
    if (status === 'blocked') {
      return res.status(403).json({ error: 'Account blocked', attemptsLeft: 5 });
    }

    const isValid = await bcrypt.compare(password, hashedPassword);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials', attemptsLeft: req.rateLimit.remaining || 4 });
    }

    const token = jwt.sign({ email, role: 'affiliate' }, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('jwt', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 3600000 });
    res.json({ token, refCode, name });
  } catch (err) {
    console.error('Error in login:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/affiliate/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  try {
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
    res.cookie('jwt', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 3600000 });
    res.json({ token });
  } catch (err) {
    console.error('Error in admin login:', err);
    res.status(500).json({ error: 'Server error' });
  }
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
  try {
    const client = await auth.getClient();
    const [details, withdrawals, rewards, notifications] = await Promise.all([
      sheets.spreadsheets.values.get({
        auth: client,
        spreadsheetId: AFFILIATES_SHEET_ID,
        range: `${email}!Details!A2:K`,
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

    if (!details.data.values) {
      return res.status(404).json({ error: 'Affiliate not found' });
    }

    res.json({
      name: details.data.values[0][1] || '',
      refCode: details.data.values[0][2] || '',
      linkClicks: parseInt(details.data.values[0][4] || '0'),
      saleCount: parseInt(details.data.values[0][5] || '0'),
      currentBalance: parseFloat(details.data.values[0][6] || '0'),
      totalEarnings: parseFloat(details.data.values[0][7] || '0'),
      withdrawals: withdrawals.data.values?.slice(-20).map(row => ({
        timestamp: row[0],
        amount: parseFloat(row[1]),
        mpesaNumber: row[2],
        mpesaName: row[3],
        status: row[4],
        mpesaRef: row[5] || '',
      })) || [],
      rewards: rewards.data.values?.map(row => ({
        timestamp: row[0],
        rewardType: row[1],
        rewardValue: parseFloat(row[2]),
        duration: parseInt(row[3] || '0'),
        endDate: row[4] || '',
      })) || [],
      notifications: notifications.data.values?.map(row => ({
        timestamp: row[0],
        message: row[1],
        read: row[2] === 'true',
      })) || [],
      leaderboard: cachedDataAffiliate.leaderboard,
    });
  } catch (err) {
    console.error('Error fetching affiliate data:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/affiliate/data', async (req, res) => {
  try {
    res.json({
      settings: cachedDataAffiliate.settings,
      staticPages: cachedDataAffiliate.staticPages,
    });
  } catch (err) {
    console.error('Error fetching admin data:', err);
    res.status(500).json({ error: 'Server error' });
  }
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
app.post('/api/affiliate/track-click', authenticateApiKey, async (req, res) => {
  const { refCode } = req.body;
  if (!refCode) {
    return res.status(400).json({ error: 'RefCode required' });
  }

  try {
    const affiliate = cachedDataAffiliate.affiliates.find(a => a.refCode === refCode);
    if (!affiliate) {
      return res.status(404).json({ error: 'Affiliate not found' });
    }

    const client = await auth.getClient();
    const details = await sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${affiliate.email}!Details!A2:K`,
    });

    if (!details.data.values) {
      return res.status(404).json({ error: 'Affiliate data not found' });
    }

    const row = details.data.values[0];
    row[4] = parseInt(row[4] || '0') + 1; // Increment LinkClicks

    await sheets.spreadsheets.values.update({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${affiliate.email}!Details!A2:K`,
      valueInputOption: 'RAW',
      resource: { values: [row] },
    });

    const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.email === affiliate.email);
    cachedDataAffiliate.affiliates[affiliateIndex].linkClicks = row[4];
    io.emit('update', cachedDataAffiliate);

    res.json({ success: true });
  } catch (err) {
    console.error('Error tracking click:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/affiliate/confirmed-sale', authenticateApiKey, async (req, res) => {
  const { refCode, amount, item } = req.body;
  if (!refCode || !amount || !item) {
    return res.status(400).json({ error: 'RefCode, amount, and item required' });
  }

  try {
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
      range: `${affiliate.email}!Details!A2:K`,
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
      range: `${affiliate.email}!Details!A2:K`,
      valueInputOption: 'RAW',
      resource: { values: [row] },
    });

    await sheets.spreadsheets.values.append({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${affiliate.email}!Rewards!A2`,
      valueInputOption: 'RAW',
      resource: {
        values: [[new Date().toISOString(), 'commission', commission, 0, '']],
      },
    });

    await sheets.spreadsheets.values.append({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${affiliate.email}!Notifications!A2`,
      valueInputOption: 'RAW',
      resource: {
        values: [[new Date().toISOString(), `Commission of KES ${commission.toFixed(2)} credited for sale of ${item}`, 'false']],
      },
    });

    // Handle referrer bonus (5% of commission)
    if (affiliate.referrerEmail) {
      const referrer = cachedDataAffiliate.affiliates.find(a => a.email === affiliate.referrerEmail);
      if (referrer) {
        const referrerCommission = commission * 0.05;
        const referrerDetails = await sheets.spreadsheets.values.get({
          auth: client,
          spreadsheetId: AFFILIATES_SHEET_ID,
          range: `${referrer.email}!Details!A2:K`,
        });

        if (referrerDetails.data.values) {
          const referrerRow = referrerDetails.data.values[0];
          referrerRow[6] = parseFloat(referrerRow[6] || '0') + referrerCommission;
          referrerRow[7] = parseFloat(referrerRow[7] || '0') + referrerCommission;

          await sheets.spreadsheets.values.update({
            auth: client,
            spreadsheetId: AFFILIATES_SHEET_ID,
            range: `${referrer.email}!Details!A2:K`,
            valueInputOption: 'RAW',
            resource: { values: [referrerRow] },
          });

          await sheets.spreadsheets.values.append({
            auth: client,
            spreadsheetId: AFFILIATES_SHEET_ID,
            range: `${referrer.email}!Rewards!A2`,
            valueInputOption: 'RAW',
            resource: {
              values: [[new Date().toISOString(), 'referrer_bonus', referrerCommission, 0, '']],
            },
          });

          await sheets.spreadsheets.values.append({
            auth: client,
            spreadsheetId: AFFILIATES_SHEET_ID,
            range: `${referrer.email}!Notifications!A2`,
            valueInputOption: 'RAW',
            resource: {
              values: [[new Date().toISOString(), `Referrer bonus of KES ${referrerCommission.toFixed(2)} credited for ${affiliate.name}'s sale`, 'false']],
            },
          });

          const referrerIndex = cachedDataAffiliate.affiliates.findIndex(a => a.email === referrer.email);
          cachedDataAffiliate.affiliates[referrerIndex].totalEarnings = referrerRow[7];
        }
      }
    }

    const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.email === affiliate.email);
    cachedDataAffiliate.affiliates[affiliateIndex].saleCount = row[5];
    cachedDataAffiliate.affiliates[affiliateIndex].totalEarnings = row[7];
    cachedDataAffiliate.leaderboard = cachedDataAffiliate.affiliates
      .sort((a, b) => b.saleCount - a.saleCount)
      .slice(0, 10)
      .map(a => ({ name: a.name, saleCount: a.saleCount }));
    io.emit('update', cachedDataAffiliate);

    res.json({ success: true });
  } catch (err) {
    console.error('Error processing confirmed sale:', err);
    res.status(500).json({ error: 'Server error' });
  }
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

  try {
    const client = await auth.getClient();
    const details = await sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${email}!Details!A2:K`,
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
    details.data.values[0][6] = parseFloat(currentBalance) - amount;

    await sheets.spreadsheets.values.update({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${email}!Details!A2:K`,
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

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: cachedDataAffiliate.settings.adminEmail,
      subject: 'New Withdrawal Request',
      text: `Affiliate ${email} requested a withdrawal of KES ${amount} to Mpesa ${mpesaNumber} (${mpesaName}).`,
    });

    res.json({ success: true });
  } catch (err) {
    console.error('Error requesting withdrawal:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/affiliate/withdrawals/confirm', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const { email, timestamp, amount, mpesaNumber, mpesaName, mpesaRef } = req.body;
  if (!email || !timestamp || !amount || !mpesaNumber || !mpesaName || !mpesaRef) {
    return res.status(400).json({ error: 'All fields required' });
  }

  try {
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
  } catch (err) {
    console.error('Error confirming withdrawal:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/affiliate/withdrawals/dispute', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const { email, timestamp, amount, mpesaNumber, mpesaName } = req.body;
  if (!email || !timestamp || !amount || !mpesaNumber || !mpesaName) {
    return res.status(400).json({ error: 'All fields required' });
  }

  try {
    const client = await auth.getClient();
    const details = await sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${email}!Details!A2:K`,
    });

    if (!details.data.values) {
      return res.status(404).json({ error: 'Affiliate not found' });
    }

    details.data.values[0][6] = parseFloat(details.data.values[0][6] || '0') + amount;

    await sheets.spreadsheets.values.update({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${email}!Details!A2:K`,
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
  } catch (err) {
    console.error('Error disputing withdrawal:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// NOTIFICATION ENDPOINTS
app.post('/api/affiliate/notifications/mark-read', authenticateToken, async (req, res) => {
  const { email } = req.user;
  const { timestamp } = req.body;

  if (!timestamp) {
    return res.status(400).json({ error: 'Timestamp required' });
  }

  try {
    const client = await auth.getClient();
    const notifications = await sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${email}!Notifications!A2:C`,
    });

    if (!notifications.data.values) {
      return res.status(404).json({ error: 'Notifications not found' });
    }

    const updatedNotifications = notifications.data.values.map(row => 
      row[0] === timestamp ? [row[0], row[1], 'true'] : row
    );

    await sheets.spreadsheets.values.update({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${email}!Notifications!A2:C`,
      valueInputOption: 'RAW',
      resource: { values: updatedNotifications },
    });

    res.json({ success: true });
  } catch (err) {
    console.error('Error marking notification as read:', err);
    res.status(500).json({ error: 'Server error' });
  }
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

  try {
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
        range: `${affiliate.email}!Details!A2:K`,
      });

      if (!details.data.values) continue;

      const row = details.data.values[0];
      let amount = 0;
      if (rewardType === 'fixed') {
        amount = parseFloat(rewardValue);
      } else if (rewardType === 'percentage') {
        amount = parseFloat(row[7] || '0') * (parseFloat(rewardValue) / 100);
      } else if (rewardType === 'commission') {
        amount = parseFloat(rewardValue) / 100;
      }

      if (rewardType !== 'commission') {
        row[6] = parseFloat(row[6] || '0') + amount;
        row[7] = parseFloat(row[7] || '0') + amount;
      }

      await sheets.spreadsheets.values.update({
        auth: client,
        spreadsheetId: AFFILIATES_SHEET_ID,
        range: `${affiliate.email}!Details!A2:K`,
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
        spreadsheetId: AFFILIATES_SHEET_ID,
        range: `${affiliate.email}!Notifications!A2`,
        valueInputOption: 'RAW',
        resource: {
          values: [[new Date().toISOString(), `Reward of KES ${amount.toFixed(2)} credited for ${rewardType}`, 'false']],
        },
      });

      const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.email === affiliate.email);
      if (affiliateIndex !== -1 && rewardType !== 'commission') {
        cachedDataAffiliate.affiliates[affiliateIndex].totalEarnings = row[7];
      }
    }

    await sheets.spreadsheets.values.append({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'leaderboard!A2',
      valueInputOption: 'RAW',
      resource: {
        values: eligibleAffiliates.map(a => [rewardId, a.name, rewardType, rewardValue, endDate, 'true']),
      },
    });

    cachedDataAffiliate.leaderboard = cachedDataAffiliate.affiliates
      .sort((a, b) => b.saleCount - a.saleCount)
      .slice(0, 10)
      .map(a => ({ name: a.name, saleCount: a.saleCount }));
    io.emit('update', cachedDataAffiliate);

    res.json({ success: true });
  } catch (err) {
    console.error('Error processing rewards:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/affiliate/rewards/terminate', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const { rewardId } = req.body;
  if (!rewardId) {
    return res.status(400).json({ error: 'Reward ID required' });
  }

  try {
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

    cachedDataAffiliate.leaderboard = cachedDataAffiliate.affiliates
      .sort((a, b) => b.saleCount - a.saleCount)
      .slice(0, 10)
      .map(a => ({ name: a.name, saleCount: a.saleCount }));
    io.emit('update', cachedDataAffiliate);

    res.json({ success: true });
  } catch (err) {
    console.error('Error terminating reward:', err);
    res.status(500).json({ error: 'Server error' });
  }
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

  try {
    const client = await auth.getClient();
    if (action === 'create') {
      const newSlug = `/affiliate-${title.toLowerCase().replace(/\s+/g, '-')}`;
      const sanitizedContent = sanitizeHtml(content, { allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img']) });
      await sheets.spreadsheets.values.append({
        auth: client,
        spreadsheetId: ADMIN_SHEET_ID,
        range: 'staticPagesAffiliate!A2',
        valueInputOption: 'RAW',
        resource: {
          values: [[newSlug, title, sanitizedContent]],
        },
      });
      cachedDataAffiliate.staticPages.push({ slug: newSlug, title, content: sanitizedContent });
    } else if (action === 'edit') {
      const pages = await sheets.spreadsheets.values.get({
        auth: client,
        spreadsheetId: ADMIN_SHEET_ID,
        range: 'staticPagesAffiliate!A2:C',
      });

      const sanitizedContent = sanitizeHtml(content, { allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img']) });
      const updatedPages = pages.data.values?.map(row => 
        row[0] === slug ? [slug, title, sanitizedContent] : row
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
        cachedDataAffiliate.staticPages[pageIndex] = { slug, title, content: sanitizedContent };
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
  } catch (err) {
    console.error('Error managing static pages:', err);
    res.status(500).json({ error: 'Server error' });
  }
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

  try {
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
  } catch (err) {
    console.error('Error sending communication:', err);
    res.status(500).json({ error: 'Server error' });
  }
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

  try {
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
  } catch (err) {
    console.error('Error updating settings:', err);
    res.status(500).json({ error: 'Server error' });
  }
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

  try {
    const client = await auth.getClient();
    const details = await sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${email}!Details!A2:K`,
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
      range: `${email}!Details!A2:K`,
      valueInputOption: 'RAW',
      resource: { values: details.data.values },
    });

    io.emit('forceLogout', { email });
    res.json({ success: true });
  } catch (err) {
    console.error('Error updating password:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/affiliate/delete-account', authenticateToken, async (req, res) => {
  const { email } = req.user;
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ error: 'Password required' });
  }

  try {
    const client = await auth.getClient();
    const details = await sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${email}!Details!A2:K`,
    });

    if (!details.data.values) {
      return res.status(404).json({ error: 'Affiliate not found' });
    }

    const [_, __, ___, hashedPassword, ____, _____, currentBalance] = details.data.values[0];
    const isValid = await bcrypt.compare(password, hashedPassword);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    if (parseFloat(currentBalance) > 0) {
      return res.status(400).json({ error: 'Cannot delete account with non-zero balance' });
    }

    const pending = await sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: ADMIN_SHEET_ID,
      range: 'pendingWithdrawals!A2:E',
    });

    if (pending.data.values?.some(row => row[0] === email)) {
      return res.status(400).json({ error: 'Cannot delete account with pending withdrawals' });
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
    cachedDataAffiliate.leaderboard = cachedDataAffiliate.affiliates
      .sort((a, b) => b.saleCount - a.saleCount)
      .slice(0, 10)
      .map(a => ({ name: a.name, saleCount: a.saleCount }));
    io.emit('update', cachedDataAffiliate);
    io.emit('forceLogout', { email });

    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting account:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// BLOCKING ENDPOINT
app.post('/api/admin/affiliate/block', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }

  try {
    const client = await auth.getClient();
    const affiliate = cachedDataAffiliate.affiliates.find(a => a.email === email);
    if (!affiliate) {
      return res.status(404).json({ error: 'Affiliate not found' });
    }

    const details = await sheets.spreadsheets.values.get({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${email}!Details!A2:K`,
    });

    if (!details.data.values) {
      return res.status(404).json({ error: 'Affiliate data not found' });
    }

    details.data.values[0][9] = 'blocked'; // Update Status to blocked

    await sheets.spreadsheets.values.update({
      auth: client,
      spreadsheetId: AFFILIATES_SHEET_ID,
      range: `${email}!Details!A2:K`,
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

    const affiliateIndex = cachedDataAffiliate.affiliates.findIndex(a => a.email === email);
    if (affiliateIndex !== -1) {
      cachedDataAffiliate.affiliates[affiliateIndex].status = 'blocked';
    }
    io.emit('update', cachedDataAffiliate);
    io.emit('forceLogout', { email });

    res.json({ success: true });
  } catch (err) {
    console.error('Error blocking affiliate:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// WebSocket connection handler
io.on('connection', (socket) => {
  socket.emit('update', cachedDataAffiliate);

  socket.on('disconnect', () => {
    console.log('WebSocket client disconnected');
  });
});

// Start server
const PORT = process.env.PORT || 3000;
const initializeAndStart = async () => {
  try {
    await initializeSheets();
    await loadCachedData();
    server.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Failed to initialize server:', err);
    process.exit(1);
  }
};

initializeAndStart();
