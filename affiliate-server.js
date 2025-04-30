require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const { google } = require('googleapis');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const WebSocket = require('ws');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.AFFILIATE_PORT || 10001;
const API_KEY = process.env.AFFILIATE_API_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret';

// Google Sheets Setup
const sheets = google.sheets({ version: 'v4', auth: new google.auth.GoogleAuth({
    credentials: JSON.parse(process.env.GOOGLE_CREDENTIALS),
    scopes: ['https://www.googleapis.com/auth/spreadsheets']
}) });

// Nodemailer Setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER_WITHDRAWAL,
        pass: process.env.EMAIL_WITHDRAWAL_PASS
    }
});

// WebSocket Setup
const wss = new WebSocket.Server({ noServer: true });
const clients = new Map(); // Map<email, WebSocket>

// Cache
let cachedDataAffiliate = {
    affiliates: [],
    settingsAffiliate: {
        commissionRate: 0.2,
        supportEmail: 'support@botblitz.store',
        copyrightText: '© 2025 BotBlitz Affiliates',
        whatsappLink: '',
        adminEmail: 'admin@botblitz.store',
        adminPassword: '' // Hashed
    },
    staticPagesAffiliate: []
};

// Middleware
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(',') || ['https://botblitz.store'], credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-session-secret',
    resave: false,
    saveUninitialized: false,
    store: new session.MemoryStore(),
    cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true }
}));

// Rate Limiting
const loginLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 5,
    message: 'Too many login attempts. Try again later.'
});
app.use('/api/affiliate/login', loginLimiter);
app.use('/api/admin/affiliate/login', loginLimiter);

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Google Sheets Functions
async function ensureSheetTabs() {
    const spreadsheetIds = [process.env.AFFILIATES_SHEET_ID, process.env.ADMIN_SHEET_ID];
    for (const spreadsheetId of spreadsheetIds) {
        const spreadsheet = await sheets.spreadsheets.get({ spreadsheetId });
        const existingTabs = spreadsheet.data.sheets.map(sheet => sheet.properties.title);

        if (spreadsheetId === process.env.ADMIN_SHEET_ID) {
            const tabs = [
                { name: 'settingsAffiliate', headers: ['KEY', 'VALUE'] },
                { name: 'staticPagesAffiliate', headers: ['Slug', 'Title', 'Content'] },
                { name: 'blocklist', headers: ['Email', 'Timestamp'] }
            ];
            for (const tab of tabs) {
                if (!existingTabs.includes(tab.name)) {
                    await sheets.spreadsheets.batchUpdate({
                        spreadsheetId,
                        resource: {
                            requests: [{ addSheet: { properties: { title: tab.name } } }]
                        }
                    });
                    await sheets.spreadsheets.values.update({
                        spreadsheetId,
                        range: `${tab.name}!A1`,
                        valueInputOption: 'RAW',
                        resource: { values: [tab.headers] }
                    });
                }
            }
        }
    }
}

async function createAffiliateSheet(email, data) {
    const spreadsheetId = process.env.AFFILIATES_SHEET_ID;
    await sheets.spreadsheets.batchUpdate({
        spreadsheetId,
        resource: {
            requests: [{ addSheet: { properties: { title: email } } }]
        }
    });
    const tabs = [
        { name: 'Details', headers: ['Name', 'Email', 'HashedPassword', 'RefCode', 'LinkClicks', 'TotalSales', 'CurrentBalance', 'Status', 'Referrer', 'MpesaNumber', 'MpesaName', 'ReuseDetails'] },
        { name: 'Withdrawals', headers: ['Timestamp', 'Amount', 'MpesaNumber', 'MpesaName', 'Status', 'MpesaRef'] },
        { name: 'Rewards', headers: ['Timestamp', 'Type', 'Amount', 'Description'] },
        { name: 'Notifications', headers: ['Timestamp', 'Message', 'Read'] }
    ];
    for (const tab of tabs) {
        await sheets.spreadsheets.values.update({
            spreadsheetId,
            range: `${email}!${tab.name}!A1`,
            valueInputOption: 'RAW',
            resource: { values: [tab.headers] }
        });
    }
    await sheets.spreadsheets.values.append({
        spreadsheetId,
        range: `${email}!Details!A2`,
        valueInputOption: 'RAW',
        resource: { values: [[
            data.name, email, data.hashedPassword, data.refCode, 0, 0, 0, 'active',
            data.referrer || '', '', '', false
        ]] }
    });
}

// Authentication Middleware
function authenticateJWT(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.deviceId !== req.headers['x-device-id']) {
            return res.status(401).json({ error: 'Session expired. Please login.' });
        }
        req.user = decoded;
        next();
    });
}

function authenticateAdmin(req, res, next) {
    if (!req.session.isAuthenticatedAffiliate) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
}

// Routes
app.post('/api/affiliate/register', async (req, res) => {
    try {
        const { fullName, email, password, terms, referrer } = req.body;
        if (!fullName || fullName.split(' ').length < 2 || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
            !password || password.length < 8 || !/[a-zA-Z]/.test(password) || !terms) {
            return res.status(400).json({ error: 'All fields required' });
        }

        const blocklist = await sheets.spreadsheets.values.get({
            spreadsheetId: process.env.ADMIN_SHEET_ID,
            range: 'blocklist!A:A'
        });
        if (blocklist.data.values?.some(row => row[0] === email)) {
            return res.status(403).json({ error: 'Account creation blocked. Contact support.' });
        }

        const sheetsList = await sheets.spreadsheets.get({ spreadsheetId: process.env.AFFILIATES_SHEET_ID });
        if (sheetsList.data.sheets.some(sheet => sheet.properties.title === email)) {
            return res.status(400).json({ error: 'Email exists. Please login.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const refCode = uuidv4().replace(/-/g, '').slice(0, 10);
        await createAffiliateSheet(email, { name: fullName, hashedPassword, refCode, referrer });
        const token = jwt.sign({ email, deviceId: req.headers['x-device-id'] }, JWT_SECRET, { expiresIn: '7d' });
        cachedDataAffiliate.affiliates.push({ email, name: fullName, refCode, linkClicks: 0, totalSales: 0, currentBalance: 0, status: 'active' });
        res.json({ token, name: fullName, refCode });
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Register error:`, error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/affiliate/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

        const blocklist = await sheets.spreadsheets.values.get({
            spreadsheetId: process.env.ADMIN_SHEET_ID,
            range: 'blocklist!A:A'
        });
        if (blocklist.data.values?.some(row => row[0] === email)) {
            return res.status(403).json({ error: 'Account blocked. Contact support.' });
        }

        const details = await sheets.spreadsheets.values.get({
            spreadsheetId: process.env.AFFILIATES_SHEET_ID,
            range: `${email}!Details!A2:L2`
        });
        if (!details.data.values?.length) return res.status(401).json({ error: 'Invalid credentials' });

        const [name, , hashedPassword, refCode] = details.data.values[0];
        if (await bcrypt.compare(password, hashedPassword)) {
            const token = jwt.sign({ email, deviceId: req.headers['x-device-id'] }, JWT_SECRET, { expiresIn: '7d' });
            res.json({ token, name, refCode });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Login error:`, error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/affiliate/data', authenticateJWT, async (req, res) => {
    try {
        const email = req.user.email;
        const details = await sheets.spreadsheets.values.get({
            spreadsheetId: process.env.AFFILIATES_SHEET_ID,
            range: `${email}!Details!A2:L2`
        });
        if (!details.data.values?.length || details.data.values[0][7] === 'blocked') {
            return res.status(403).json({ error: 'Account blocked. Contact support.' });
        }

        const [name, , , refCode, linkClicks, totalSales, currentBalance] = details.data.values[0];
        const withdrawals = await sheets.spreadsheets.values.get({
            spreadsheetId: process.env.AFFILIATES_SHEET_ID,
            range: `${email}!Withdrawals!A2:F`
        });
        const rewards = await sheets.spreadsheets.values.get({
            spreadsheetId: process.env.AFFILIATES_SHEET_ID,
            range: `${email}!Rewards!A2:D`
        });
        const notifications = await sheets.spreadsheets.values.get({
            spreadsheetId: process.env.AFFILIATES_SHEET_ID,
            range: `${email}!Notifications!A2:C`
        });

        const sortedWithdrawals = (withdrawals.data.values || []).sort((a, b) => new Date(b[0]) - new Date(a[0])).slice(0, 20);
        const unreadNotifications = (notifications.data.values || []).filter(n => n[2] !== 'true');
        const leaderboard = cachedDataAffiliate.affiliates
            .sort((a, b) => b.totalSales - a.totalSales)
            .slice(0, 10)
            .map(a => ({ name: a.name, totalSales: a.totalSales }));

        res.json({
            name,
            refCode,
            linkClicks: parseInt(linkClicks),
            totalSales: parseInt(totalSales),
            currentBalance: parseFloat(currentBalance),
            withdrawals: sortedWithdrawals,
            rewards: rewards.data.values || [],
            notifications: notifications.data.values || [],
            unreadCount: unreadNotifications.length,
            monthlyCommission: totalSales * cachedDataAffiliate.settingsAffiliate.commissionRate,
            leaderboard
        });
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Dashboard data error:`, error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/affiliate/track-click', async (req, res) => {
    try {
        if (req.headers['x-api-key'] !== API_KEY) return res.status(401).json({ error: 'Unauthorized' });
        const { refCode } = req.body;
        const affiliate = cachedDataAffiliate.affiliates.find(a => a.refCode === refCode);
        if (!affiliate) return res.status(404).json({ error: 'Invalid refCode' });

        await sheets.spreadsheets.values.update({
            spreadsheetId: process.env.AFFILIATES_SHEET_ID,
            range: `${affiliate.email}!Details!E2`,
            valueInputOption: 'RAW',
            resource: { values: [[parseInt(affiliate.linkClicks) + 1]] }
        });
        affiliate.linkClicks++;
        if (clients.has(affiliate.email)) {
            clients.get(affiliate.email).send(JSON.stringify({ type: 'linkClick', count: affiliate.linkClicks }));
        }
        res.json({ message: 'Click tracked' });
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Track click error:`, error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/affiliate/confirmed-sale', async (req, res) => {
    try {
        if (req.headers['x-api-key'] !== API_KEY) return res.status(401).json({ error: 'Unauthorized' });
        const { refCode, item, amount } = req.body;
        const affiliate = cachedDataAffiliate.affiliates.find(a => a.refCode === refCode);
        if (!affiliate) return res.status(404).json({ error: 'Invalid refCode' });

        const commission = amount * cachedDataAffiliate.settingsAffiliate.commissionRate;
        const newTotalSales = affiliate.totalSales + 1;
        const newBalance = affiliate.currentBalance + commission;

        await sheets.spreadsheets.values.update({
            spreadsheetId: process.env.AFFILIATES_SHEET_ID,
            range: `${affiliate.email}!Details!F2:G2`,
            valueInputOption: 'RAW',
            resource: { values: [[newTotalSales, newBalance]] }
        });

        affiliate.totalSales = newTotalSales;
        affiliate.currentBalance = newBalance;

        const referrer = cachedDataAffiliate.affiliates.find(a => a.refCode === affiliate.referrer);
        if (referrer) {
            const referralBonus = commission * 0.05;
            referrer.currentBalance += referralBonus;
            await sheets.spreadsheets.values.update({
                spreadsheetId: process.env.AFFILIATES_SHEET_ID,
                range: `${referrer.email}!Details!G2`,
                valueInputOption: 'RAW',
                resource: { values: [[referrer.currentBalance]] }
            });
            await sheets.spreadsheets.values.append({
                spreadsheetId: process.env.AFFILIATES_SHEET_ID,
                range: `${referrer.email}!Rewards!A2`,
                valueInputOption: 'RAW',
                resource: { values: [[new Date().toISOString(), 'Referral Bonus', referralBonus, `From ${affiliate.email}`]] }
            });
        }

        res.json({ message: 'Sale credited' });
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Confirmed sale error:`, error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/affiliate/request-withdrawal', authenticateJWT, async (req, res) => {
    try {
        const { amount, mpesaNumber, mpesaName, reuseDetails, password } = req.body;
        const email = req.user.email;
        const details = await sheets.spreadsheets.values.get({
            spreadsheetId: process.env.AFFILIATES_SHEET_ID,
            range: `${email}!Details!A2:L2`
        });
        if (!details.data.values?.length) return res.status(404).json({ error: 'Account not found' });

        const [, , hashedPassword, , , , currentBalance] = details.data.values[0];
        if (!await bcrypt.compare(password, hashedPassword)) {
            return res.status(401).json({ error: 'Invalid password' });
        }
        if (parseFloat(amount) > parseFloat(currentBalance) || parseFloat(amount) <= 0) {
            return res.status(400).json({ error: 'Invalid withdrawal amount' });
        }

        const newBalance = parseFloat(currentBalance) - parseFloat(amount);
        await sheets.spreadsheets.values.update({
            spreadsheetId: process.env.AFFILIATES_SHEET_ID,
            range: `${email}!Details!G2`,
            valueInputOption: 'RAW',
            resource: { values: [[newBalance]] }
        });
        if (reuseDetails) {
            await sheets.spreadsheets.values.update({
                spreadsheetId: process.env.AFFILIATES_SHEET_ID,
                range: `${email}!Details!J2:L2`,
                valueInputOption: 'RAW',
                resource: { values: [[mpesaNumber, mpesaName, true]] }
            });
        }
        await sheets.spreadsheets.values.append({
            spreadsheetId: process.env.AFFILIATES_SHEET_ID,
            range: `${email}!Withdrawals!A2`,
            valueInputOption: 'RAW',
            resource: { values: [[new Date().toISOString(), amount, mpesaNumber, mpesaName, 'Pending', '']] }
        });

        const affiliate = cachedDataAffiliate.affiliates.find(a => a.email === email);
        affiliate.currentBalance = newBalance;

        await transporter.sendMail({
            from: process.env.EMAIL_USER_WITHDRAWAL,
            to: cachedDataAffiliate.settingsAffiliate.adminEmail,
            subject: `Affiliate Withdrawal - ${details.data.values[0][0]} ${amount}`,
            text: `Verify new withdrawal:\nM-PESA Number: ${mpesaNumber}\nM-PESA Name: ${mpesaName}`
        });

        res.json({ message: 'Withdrawal submitted' });
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Withdrawal request error:`, error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/affiliate/update-password', authenticateJWT, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        if (!newPassword || newPassword.length < 8 || !/[a-zA-Z]/.test(newPassword)) {
            return res.status(400).json({ error: 'Invalid new password' });
        }

        const email = req.user.email;
        const details = await sheets.spreadsheets.values.get({
            spreadsheetId: process.env.AFFILIATES_SHEET_ID,
            range: `${email}!Details!A2:L2`
        });
        if (!await bcrypt.compare(oldPassword, details.data.values[0][2])) {
            return res.status(401).json({ error: 'Invalid old password' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await sheets.spreadsheets.values.update({
            spreadsheetId: process.env.AFFILIATES_SHEET_ID,
            range: `${email}!Details!C2`,
            valueInputOption: 'RAW',
            resource: { values: [[hashedPassword]] }
        });

        res.json({ message: 'Password updated. Please login again.' });
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Update password error:`, error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/affiliate/delete-account', authenticateJWT, async (req, res) => {
    try {
        const { password } = req.body;
        const email = req.user.email;
        const details = await sheets.spreadsheets.values.get({
            spreadsheetId: process.env.AFFILIATES_SHEET_ID,
            range: `${email}!Details!A2:L2`
        });
        if (!await bcrypt.compare(password, details.data.values[0][2])) {
            return res.status(401).json({ error: 'Invalid password' });
        }
        if (parseFloat(details.data.values[0][6]) > 0) {
            return res.status(400).json({ error: 'Clear balance first' });
        }

        const withdrawals = await sheets.spreadsheets.values.get({
            spreadsheetId: process.env.AFFILIATES_SHEET_ID,
            range: `${email}!Withdrawals!A2:F`
        });
        if (withdrawals.data.values?.some(w => w[4] === 'Pending')) {
            return res.status(400).json({ error: 'Resolve pending withdrawals first' });
        }

        await sheets.spreadsheets.values.append({
            spreadsheetId: process.env.ADMIN_SHEET_ID,
            range: 'blocklist!A2',
            valueInputOption: 'RAW',
            resource: { values: [[email, new Date().toISOString()]] }
        });

        const sheetId = (await sheets.spreadsheets.get({
            spreadsheetId: process.env.AFFILIATES_SHEET_ID
        })).data.sheets.find(s => s.properties.title === email).properties.sheetId;
        await sheets.spreadsheets.batchUpdate({
            spreadsheetId: process.env.AFFILIATES_SHEET_ID,
            resource: { requests: [{ deleteSheet: { sheetId } }] }
        });

        cachedDataAffiliate.affiliates = cachedDataAffiliate.affiliates.filter(a => a.email !== email);
        res.json({ message: 'Account deleted' });
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Delete account error:`, error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/admin/affiliate/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (email !== cachedDataAffiliate.settingsAffiliate.adminEmail ||
            !await bcrypt.compare(password, cachedDataAffiliate.settingsAffiliate.adminPassword)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        req.session.isAuthenticatedAffiliate = true;
        res.json({ message: 'Logged in' });
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Admin login error:`, error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/admin/affiliate/affiliates', authenticateAdmin, async (req, res) => {
    try {
        const { search, sort } = req.query;
        let affiliates = cachedDataAffiliate.affiliates.map(a => ({
            name: a.name,
            email: a.email,
            joinDate: a.joinDate || new Date().toISOString(),
            linkClicks: a.linkClicks,
            totalSales: a.totalSales,
            currentBalance: a.currentBalance,
            totalWithdrawn: a.totalWithdrawn || 0
        }));

        if (search) {
            affiliates = affiliates.filter(a => a.name.toLowerCase().includes(search.toLowerCase()));
        }
        if (sort) {
            affiliates.sort((a, b) => {
                if (sort === 'sales') return b.totalSales - a.totalSales;
                if (sort === 'withdrawals') return b.totalWithdrawn - a.totalWithdrawn;
                if (sort === 'linkClicks') return a.linkClicks - b.linkClicks;
                return 0;
            });
        }

        res.json({ affiliates });
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Admin affiliates error:`, error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/admin/affiliate/affiliates/:action', authenticateAdmin, async (req, res) => {
    try {
        const { email } = req.body;
        const action = req.params.action;
        const affiliate = cachedDataAffiliate.affiliates.find(a => a.email === email);
        if (!affiliate) return res.status(404).json({ error: 'Affiliate not found' });

        if (action === 'block') {
            await sheets.spreadsheets.values.update({
                spreadsheetId: process.env.AFFILIATES_SHEET_ID,
                range: `${email}!Details!H2`,
                valueInputOption: 'RAW',
                resource: { values: [['blocked']] }
            });
            affiliate.status = 'blocked';
            if (clients.has(email)) {
                clients.get(email).send(JSON.stringify({ type: 'logout', message: 'Account blocked. Contact support.' }));
                clients.get(email).close();
                clients.delete(email);
            }
        } else if (action === 'delete') {
            await sheets.spreadsheets.values.append({
                spreadsheetId: process.env.ADMIN_SHEET_ID,
                range: 'blocklist!A2',
                valueInputOption: 'RAW',
                resource: { values: [[email, new Date().toISOString()]] }
            });
            const sheetId = (await sheets.spreadsheets.get({
                spreadsheetId: process.env.AFFILIATES_SHEET_ID
            })).data.sheets.find(s => s.properties.title === email).properties.sheetId;
            await sheets.spreadsheets.batchUpdate({
                spreadsheetId: process.env.AFFILIATES_SHEET_ID,
                resource: { requests: [{ deleteSheet: { sheetId } }] }
            });
            cachedDataAffiliate.affiliates = cachedDataAffiliate.affiliates.filter(a => a.email !== email);
            if (clients.has(email)) {
                clients.get(email).send(JSON.stringify({ type: 'logout', message: 'Account deleted.' }));
                clients.get(email).close();
                clients.delete(email);
            }
        } else {
            return res.status(400).json({ error: 'Invalid action' });
        }
        res.json({ message: `${action} successful` });
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Admin affiliates action error:`, error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/admin/affiliate/withdrawals', authenticateAdmin, async (req, res) => {
    try {
        const withdrawals = [];
        for (const affiliate of cachedDataAffiliate.affiliates) {
            const data = await sheets.spreadsheets.values.get({
                spreadsheetId: process.env.AFFILIATES_SHEET_ID,
                range: `${affiliate.email}!Withdrawals!A2:F`
            });
            if (data.data.values) {
                withdrawals.push(...data.data.values
                    .filter(w => w[4] === 'Pending')
                    .map(w => ({ email: affiliate.email, timestamp: w[0], amount: w[1], mpesaNumber: w[2], mpesaName: w[3] })));
            }
        }
        res.json({ withdrawals });
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Admin withdrawals error:`, error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/admin/affiliate/withdrawals/:action', authenticateAdmin, async (req, res) => {
    try {
        const { email, timestamp, mpesaRef } = req.body;
        const action = req.params.action;
        const withdrawals = await sheets.spreadsheets.values.get({
            spreadsheetId: process.env.AFFILIATES_SHEET_ID,
            range: `${email}!Withdrawals!A2:F`
        });
        const index = withdrawals.data.values?.findIndex(w => w[0] === timestamp && w[4] === 'Pending');
        if (index === -1) return res.status(404).json({ error: 'Withdrawal not found' });

        if (action === 'confirm') {
            withdrawals.data.values[index][4] = 'Done';
            withdrawals.data.values[index][5] = mpesaRef;
            await sheets.spreadsheets.values.update({
                spreadsheetId: process.env.AFFILIATES_SHEET_ID,
                range: `${email}!Withdrawals!A2:F`,
                valueInputOption: 'RAW',
                resource: { values: withdrawals.data.values }
            });
            if (clients.has(email)) {
                clients.get(email).send(JSON.stringify({
                    type: 'popup',
                    message: `Payment sent. M-PESA Ref: ${mpesaRef}`
                }));
            }
        } else if (action === 'dispute') {
            const amount = parseFloat(withdrawals.data.values[index][1]);
            withdrawals.data.values[index][4] = 'Failed';
            await sheets.spreadsheets.values.update({
                spreadsheetId: process.env.AFFILIATES_SHEET_ID,
                range: `${email}!Withdrawals!A2:F`,
                valueInputOption: 'RAW',
                resource: { values: withdrawals.data.values }
            });
            const details = await sheets.spreadsheets.values.get({
                spreadsheetId: process.env.AFFILIATES_SHEET_ID,
                range: `${email}!Details!A2:L2`
            });
            const newBalance = parseFloat(details.data.values[0][6]) + amount;
            await sheets.spreadsheets.values.update({
                spreadsheetId: process.env.AFFILIATES_SHEET_ID,
                range: `${email}!Details!G2`,
                valueInputOption: 'RAW',
                resource: { values: [[newBalance]] }
            });
            cachedDataAffiliate.affiliates.find(a => a.email === email).currentBalance = newBalance;
            if (clients.has(email)) {
                clients.get(email).send(JSON.stringify({
                    type: 'popup',
                    message: `Payment failed. Contact ${cachedDataAffiliate.settingsAffiliate.supportEmail}`
                }));
            }
        } else {
            return res.status(400).json({ error: 'Invalid action' });
        }
        res.json({ message: `${action} successful` });
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Admin withdrawals action error:`, error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/admin/affiliate/rewards', authenticateAdmin, async (req, res) => {
    try {
        const { type, topN, minSales, rewardType, rewardValue, duration } = req.body;
        let rewardedAffiliates = [];

        if (type === 'leaderboard') {
            rewardedAffiliates = cachedDataAffiliate.affiliates
                .sort((a, b) => b.totalSales - a.totalSales)
                .slice(0, topN);
        } else if (type === 'sales') {
            rewardedAffiliates = cachedDataAffiliate.affiliates.filter(a => a.totalSales >= minSales);
        }

        for (const affiliate of rewardedAffiliates) {
            let amount = 0;
            if (rewardType === 'fixed') amount = rewardValue;
            else if (rewardType === 'percentage') amount = affiliate.totalSales * cachedDataAffiliate.settingsAffiliate.commissionRate * (rewardValue / 100);
            else if (rewardType === 'commission') {
                // Implement commission rate adjustment (future feature)
            }
            if (amount > 0) {
                affiliate.currentBalance += amount;
                await sheets.spreadsheets.values.update({
                    spreadsheetId: process.env.AFFILIATES_SHEET_ID,
                    range: `${affiliate.email}!Details!G2`,
                    valueInputOption: 'RAW',
                    resource: { values: [[affiliate.currentBalance]] }
                });
                await sheets.spreadsheets.values.append({
                    spreadsheetId: process.env.AFFILIATES_SHEET_ID,
                    range: `${affiliate.email}!Rewards!A2`,
                    valueInputOption: 'RAW',
                    resource: { values: [[new Date().toISOString(), rewardType, amount, `Admin Reward`]] }
                });
                if (clients.has(affiliate.email)) {
                    clients.get(affiliate.email).send(JSON.stringify({
                        type: 'popup',
                        message: `Congratulations, you received a reward of ${amount} Ksh`
                    }));
                }
            }
        }

        for (const affiliate of cachedDataAffiliate.affiliates) {
            await sheets.spreadsheets.values.append({
                spreadsheetId: process.env.AFFILIATES_SHEET_ID,
                range: `${affiliate.email}!Notifications!A2`,
                valueInputOption: 'RAW',
                resource: { values: [[new Date().toISOString(), `Top ${topN} rewarded on ${new Date().toISOString()}`, false]] }
            });
        }

        res.json({ message: 'Rewards applied' });
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Admin rewards error:`, error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/admin/affiliate/staticpages', authenticateAdmin, async (req, res) => {
    res.json({ staticPages: cachedDataAffiliate.staticPagesAffiliate });
});

app.post('/api/admin/affiliate/staticpages', authenticateAdmin, async (req, res) => {
    try {
        const { action, slug, title, content } = req.body;
        if (action === 'add') {
            const newSlug = `/affiliate-${title.toLowerCase().replace(/\s+/g, '-')}`;
            cachedDataAffiliate.staticPagesAffiliate.push({ slug: newSlug, title, content });
            await sheets.spreadsheets.values.append({
                spreadsheetId: process.env.ADMIN_SHEET_ID,
                range: 'staticPagesAffiliate!A2',
                valueInputOption: 'RAW',
                resource: { values: [[newSlug, title, content]] }
            });
        } else if (action === 'edit') {
            const page = cachedDataAffiliate.staticPagesAffiliate.find(p => p.slug === slug);
            if (page) {
                page.title = title;
                page.content = content;
                const pages = await sheets.spreadsheets.values.get({
                    spreadsheetId: process.env.ADMIN_SHEET_ID,
                    range: 'staticPagesAffiliate!A2:C'
                });
                const index = pages.data.values.findIndex(p => p[0] === slug);
                pages.data.values[index] = [slug, title, content];
                await sheets.spreadsheets.values.update({
                    spreadsheetId: process.env.ADMIN_SHEET_ID,
                    range: 'staticPagesAffiliate!A2:C',
                    valueInputOption: 'RAW',
                    resource: { values: pages.data.values }
                });
            }
        } else if (action === 'delete') {
            cachedDataAffiliate.staticPagesAffiliate = cachedDataAffiliate.staticPagesAffiliate.filter(p => p.slug !== slug);
            const pages = await sheets.spreadsheets.values.get({
                spreadsheetId: process.env.ADMIN_SHEET_ID,
                range: 'staticPagesAffiliate!A2:C'
            });
            const newPages = pages.data.values.filter(p => p[0] !== slug);
            await sheets.spreadsheets.values.update({
                spreadsheetId: process.env.ADMIN_SHEET_ID,
                range: 'staticPagesAffiliate!A2:C',
                valueInputOption: 'RAW',
                resource: { values: newPages }
            });
        }
        res.json({ message: `${action} successful` });
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Admin static pages error:`, error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/admin/affiliate/communication', authenticateAdmin, async (req, res) => {
    try {
        const { type, text, filter } = req.body;
        if (type === 'popup') {
            cachedDataAffiliate.settingsAffiliate.urgentPopup = { text, enabled: true };
            await sheets.spreadsheets.values.append({
                spreadsheetId: process.env.ADMIN_SHEET_ID,
                range: 'settingsAffiliate!A2',
                valueInputOption: 'RAW',
                resource: { values: [['urgentPopup', JSON.stringify({ text, enabled: true })]] }
            });
        } else if (type === 'notification') {
            const targets = filter === 'all' ? cachedDataAffiliate.affiliates :
                cachedDataAffiliate.affiliates.filter(a => a.totalSales <= (filter || 0));
            for (const affiliate of targets) {
                await sheets.spreadsheets.values.append({
                    spreadsheetId: process.env.AFFILIATES_SHEET_ID,
                    range: `${affiliate.email}!Notifications!A2`,
                    valueInputOption: 'RAW',
                    resource: { values: [[new Date().toISOString(), text, false]] }
                });
                if (clients.has(affiliate.email)) {
                    clients.get(affiliate.email).send(JSON.stringify({ type: 'notification', message: text }));
                }
            }
        }
        res.json({ message: 'Communication sent' });
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Admin communication error:`, error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/admin/affiliate/settings', authenticateAdmin, async (req, res) => {
    try {
        const { supportEmail, copyrightText, whatsappLink, commissionRate, adminEmail, adminPassword } = req.body;
        const updates = {};
        if (supportEmail) updates.supportEmail = supportEmail;
        if (copyrightText) updates.copyrightText = copyrightText;
        if (whatsappLink) updates.whatsappLink = whatsappLink;
        if (commissionRate) updates.commissionRate = parseFloat(commissionRate);
        if (adminEmail) updates.adminEmail = adminEmail;
        if (adminPassword) updates.adminPassword = await bcrypt.hash(adminPassword, 10);

        Object.assign(cachedDataAffiliate.settingsAffiliate, updates);
        for (const [key, value] of Object.entries(updates)) {
            await sheets.spreadsheets.values.append({
                spreadsheetId: process.env.ADMIN_SHEET_ID,
                range: 'settingsAffiliate!A2',
                valueInputOption: 'RAW',
                resource: { values: [[key, typeof value === 'object' ? JSON.stringify(value) : value]] }
            });
        }
        res.json({ message: 'Settings updated' });
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Admin settings error:`, error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/ping', (req, res) => {
    if (req.headers['x-api-key'] !== API_KEY) return res.status(401).json({ error: 'Unauthorized' });
    res.json({ message: 'Pong' });
});

// WebSocket Handling
app.server = app.listen(PORT, async () => {
    await ensureSheetTabs();
    console.log(`[${new Date().toISOString()}] Affiliate server running on port ${PORT}`);
    await transporter.sendMail({
        from: process.env.EMAIL_USER_WITHDRAWAL,
        to: cachedDataAffiliate.settingsAffiliate.adminEmail,
        subject: 'Affiliate Server Started',
        text: 'Affiliate server is up and running.'
    });
});

app.server.on('upgrade', (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, ws => {
        wss.emit('connection', ws, request);
    });
});

wss.on('connection', (ws, req) => {
    const token = new URLSearchParams(req.url.split('?')[1]).get('token');
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (!err) {
            clients.set(decoded.email, ws);
            ws.on('close', () => clients.delete(decoded.email));
        } else {
            ws.close();
        }
    });
});

// Cache Refresh and Ping
setInterval(async () => {
    try {
        const affiliates = await sheets.spreadsheets.get({ spreadsheetId: process.env.AFFILIATES_SHEET_ID });
        cachedDataAffiliate.affiliates = [];
        for (const sheet of affiliates.data.sheets) {
            if (sheet.properties.title !== 'Sheet1') {
                const details = await sheets.spreadsheets.values.get({
                    spreadsheetId: process.env.AFFILIATES_SHEET_ID,
                    range: `${sheet.properties.title}!Details!A2:L2`
                });
                if (details.data.values?.length) {
                    const [name, email, , refCode, linkClicks, totalSales, currentBalance, status, referrer] = details.data.values[0];
                    cachedDataAffiliate.affiliates.push({
                        name, email, refCode, linkClicks: parseInt(linkClicks), totalSales: parseInt(totalSales),
                        currentBalance: parseFloat(currentBalance), status, referrer
                    });
                }
            }
        }
        const settings = await sheets.spreadsheets.values.get({
            spreadsheetId: process.env.ADMIN_SHEET_ID,
            range: 'settingsAffiliate!A2:B'
        });
        if (settings.data.values) {
            for (const [key, value] of settings.data.values) {
                cachedDataAffiliate.settingsAffiliate[key] = value.startsWith('{') ? JSON.parse(value) : value;
            }
        }
        const staticPages = await sheets.spreadsheets.values.get({
            spreadsheetId: process.env.ADMIN_SHEET_ID,
            range: 'staticPagesAffiliate!A2:C'
        });
        cachedDataAffiliate.staticPagesAffiliate = staticPages.data.values?.map(([slug, title, content]) => ({ slug, title, content })) || [];
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Cache refresh error:`, error.message);
    }
}, 15 * 60 * 1000);

// Inactivity Ping
let lastActivity = Date.now();
app.use((req, res, next) => {
    lastActivity = Date.now();
    next();
});
setInterval(() => {
    if (Date.now() - lastActivity > 15 * 60 * 1000) {
        console.log(`[${new Date().toISOString()}] No activity. Pinging routes...`);
        // Ping routes logic (excluding email)
    }
}, 15 * 60 * 1000);