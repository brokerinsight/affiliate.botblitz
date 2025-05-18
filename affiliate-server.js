require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
const redis = require('redis');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(express.static('public')); // Serve static files from the 'public' folder
app.use(cors({
  origin: ['https://affiliate-botblitz.onrender.com', 'https://botblitz.store', 'https://bot-delivery-system.onrender.com', 'http://localhost:10000']
}));

// Validate environment variables
const requiredEnv = ['SUPABASE_URL', 'SUPABASE_ANON', 'SUPABASE_SERVICE_ROLE', 'REDIS_URL', 'JWT_SECRET_SUPABASE', 'CAPTCHA_SECRET_KEY', 'PASSWORD_RESET_MAIL', 'PASSWORD_RESET_MAIL_PASS', 'SIGNUP_MAIL', 'SIGNUP_MAIL_PASS', 'LOGIN_MAIL', 'LOGIN_MAIL_PASS', 'WITHDRAWAL_MAIL', 'WITHDRAWAL_MAIL_PASS', 'ALERT_MAIL', 'ALERT_MAIL_PASS', 'ADMIN_MAIL', 'ADMIN_MAIL_PASS', 'REWARD_MAIL', 'REWARD_MAIL_PASS', 'API_KEY'];
for (const env of requiredEnv) {
  if (!process.env[env]) {
    console.error(`Missing environment variable: ${env}`);
    process.exit(1);
  }
}

// Initialize Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON, {
  auth: { autoRefreshToken: true, persistSession: false }
});
const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE);

// Initialize Redis
const redisClient = redis.createClient({ url: process.env.REDIS_URL });
redisClient.on('error', (err) => console.error('Redis Client Error', err.message));
(async () => {
  try {
    await redisClient.connect();
    console.log('Redis connected successfully');
  } catch (err) {
    console.error('Redis connection failed:', err.message);
  }
})();
const cachedData = { users: [], settings: [], static_pages: [], news: [], forums: [] };

// Cache refresh function
async function refreshCache() {
  try {
    const [users, settings, staticPages, news, forums] = await Promise.all([
      supabase.from('users').select('*'),
      supabase.from('settings').select('*'),
      supabase.from('static_pages').select('name, slug'),
      supabase.from('news').select('*').order('timestamp', { ascending: false }).limit(40),
      supabase.from('forums').select('*').order('createdAt', { ascending: false })
    ]);
    cachedData.users = users.data || [];
    cachedData.settings = settings.data || [];
    cachedData.static_pages = staticPages.data.map(p => ({ name: p.name, slug: p.slug })) || [];
    cachedData.news = news.data || [];
    cachedData.forums = forums.data || [];
    console.log('Cache refreshed successfully');
  } catch (err) {
    console.error('Cache refresh failed:', err.message);
  }
}
refreshCache();
setInterval(refreshCache, 15 * 60 * 1000);

// WebSocket setup
const wsClients = new Map();
const server = app.listen(process.env.PORT || 3000, () => {
  console.log(`Server running on port ${process.env.PORT || 3000}`);
});

const wsServer = new WebSocket.Server({ server });
wsServer.on('connection', (ws, request) => {
  const url = new URL(request.url, `wss://${request.headers.host}`);
  const token = url.searchParams.get('token');
  if (!token) {
    ws.close();
    return;
  }
  jwt.verify(token, process.env.JWT_SECRET_SUPABASE, async (err, decoded) => {
    if (err || !decoded.email) {
      ws.close();
      return;
    }
    const { data: user } = await supabase.from('users').select('email, status').eq('email', decoded.email).single();
    if (!user || user.status !== 'active') {
      ws.close();
      return;
    }
    wsClients.set(decoded.email, { ws, role: 'affiliate' });
    ws.on('message', (msg) => {
      const data = JSON.parse(msg.toString());
      if (data.type === 'username_check') {
        const available = !cachedData.users.some(u => u.username === data.username);
        ws.send(JSON.stringify({ type: 'username_check', available, message: available ? 'Username available' : 'Username taken' }));
      }
    });
    ws.on('close', () => wsClients.delete(decoded.email));
  });
});

// Cron jobs
const cron = require('node-cron');
cron.schedule('0 0 1 * *', async () => {
  try {
    await supabaseAdmin.from('users').update({ totalSalesMonthly: 0 }).in('status', ['active']);
    const { data: leaderboard } = await supabase.from('users').select('email, totalSalesMonthly').order('totalSalesMonthly', { ascending: false }).limit(10);
    await supabase.from('history').insert(leaderboard.map(l => ({ email: l.email, eventType: 'leaderboard', data: { totalSalesMonthly: l.totalSalesMonthly } })));
    const rewardRate = cachedData.settings.find(s => s.key === 'rewardRate')?.value || 0.2;
    for (const affiliate of leaderboard) {
      const reward = affiliate.totalSalesMonthly * rewardRate;
      await supabase.from('users').update({ currentBalance: supabase.sql`currentBalance + ${reward}` }).eq('email', affiliate.email);
      await supabase.from('history').insert({ email: affiliate.email, eventType: 'reward', data: { amount: reward, type: 'leaderboard' } });
      await sendEmail('reward_mail', affiliate.email, { name: cachedData.users.find(u => u.email === affiliate.email)?.name || 'User', amount: reward });
      wsClients.get(affiliate.email)?.ws?.send(JSON.stringify({ type: 'notification', message: `You received ${reward} KES as a reward`, color: 'green' }));
    }
    await sendEmail('admin_mail', process.env.ADMIN_MAIL, { message: 'Monthly sales reset completed' });
  } catch (err) {
    console.error('Monthly cron job failed:', err.message);
  }
});
cron.schedule('0 0 * * *', async () => {
  try {
    await supabase.from('history').delete().lt('timestamp', supabase.sql`now() - interval '30 days'`);
    const { count } = await supabase.from('news').select('id', { count: 'exact' }).order('timestamp', { ascending: false }).limit(40);
    if (count > 40) {
      await supabase.from('news').delete().gt('id', count - 40);
    }
  } catch (err) {
    console.error('Daily cron job failed:', err.message);
  }
});
setInterval(refreshCache, 15 * 60 * 1000).unref();

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.SIGNUP_MAIL, pass: process.env.SIGNUP_MAIL_PASS }
});
transporter.verify((error) => {
  if (error) console.error('Email service error:', error.message);
  else console.log('Email service ready');
});

async function sendEmail(type, to, data) {
  const getSettingValue = (key, defaultValue) => {
    const setting = cachedData.settings.find(s => s.key === key);
    if (!setting || !setting.value) return defaultValue;
    return typeof setting.value === 'string' ? setting.value : JSON.stringify(setting.value);
  };

  const templates = {
    signup_mail: { 
      subject: 'Welcome to Deriv Bot Store Affiliates', 
      html: `<img src="cid:logo" alt="Logo"><h1>Deriv Bot Store</h1><p>Hi, ${data.name}</p><p>${data.otp ? `Your account has been created. Verify with OTP: ${data.otp}` : data.message || 'Welcome!'}</p><p>${getSettingValue('copyrightText', 'Deriv Bot Store Affiliates 2025')}</p><p><a href="mailto:${getSettingValue('supportEmail', 'support@example.com')}">Support</a></p>` 
    },
    login_mail: { 
      subject: 'Login Verification', 
      html: `<img src="cid:logo" alt="Logo"><h1>Deriv Bot Store</h1><p>Hi, ${data.name}</p><p>Verify your login with OTP: ${data.otp}</p><p>${getSettingValue('copyrightText', 'Deriv Bot Store Affiliates 2025')}</p><p><a href="mailto:${getSettingValue('supportEmail', 'support@example.com')}">Support</a></p>` 
    },
    password_reset_mail: { 
      subject: 'Password Reset', 
      html: `<img src="cid:logo" alt="Logo"><h1>Deriv Bot Store</h1><p>Hi, ${data.name}</p><p>Reset your password with OTP: ${data.otp}</p><p>${getSettingValue('copyrightText', 'Deriv Bot Store Affiliates 2025')}</p><p><a href="mailto:${getSettingValue('supportEmail', 'support@example.com')}">Support</a></p>` 
    },
    withdrawal_mail: { 
      subject: 'Withdrawal Request', 
      html: `<img src="cid:logo" alt="Logo"><h1>Deriv Bot Store</h1><p>Hi, ${data.name}</p><p>${data.otp ? `Verify your withdrawal with OTP: ${data.otp}` : data.message || 'Withdrawal request processed'}</p><p>${getSettingValue('copyrightText', 'Deriv Bot Store Affiliates 2025')}</p><p><a href="mailto:${getSettingValue('supportEmail', 'support@example.com')}">Support</a></p>` 
    },
    alert_mail: { 
      subject: 'Account Alert', 
      html: `<img src="cid:logo" alt="Logo"><h1>Deriv Bot Store</h1><p>Hi, ${data.name || 'admin'}</p><p>${data.message}${data.otp ? ` OTP: ${data.otp}` : ''}</p><p>${getSettingValue('copyrightText', 'Deriv Bot Store Affiliates 2025')}</p><p><a href="mailto:${getSettingValue('supportEmail', 'support@example.com')}">Support</a></p>` 
    },
    admin_mail: { 
      subject: 'Admin Notification', 
      html: `<img src="cid:logo" alt="Logo"><h1>Deriv Bot Store</h1><p>Hi, admin</p><p>${data.message}</p><p>${getSettingValue('copyrightText', 'Deriv Bot Store Affiliates 2025')}</p><p><a href="mailto:${getSettingValue('supportEmail', 'support@example.com')}">Support</a></p>` 
    },
    reward_mail: { 
      subject: 'Reward Credited', 
      html: `<img src="cid:logo" alt="Logo"><h1>Deriv Bot Store</h1><p>Hi, ${data.name}</p><p>You received ${data.amount} KES as a reward.</p><p>${getSettingValue('copyrightText', 'Deriv Bot Store Affiliates 2025')}</p><p><a href="mailto:${getSettingValue('supportEmail', 'support@example.com')}">Support</a></p>` 
    }
  };
  const mailOptions = {
    from: process.env[type.toUpperCase().replace(/_/g, '')],
    to,
    subject: templates[type].subject,
    html: templates[type].html,
    attachments: [{ filename: 'logo.png', path: 'public/assets/logo.png', cid: 'logo' }]
  };
  try {
    await transporter.sendMail(mailOptions);
    console.log(`Email ${type} sent to ${to}`);
  } catch (error) {
    console.error(`Email ${type} failed to ${to}:`, error.message);
  }
}

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5,
  keyGenerator: (req) => req.body.email || req.ip,
  handler: (req, res) => {
    const user = cachedData.users.find(u => u.email === req.body.email && u.status === 'active');
    if (user) {
      res.status(429).json({ success: false, error: `Rate limit exceeded, try again in ${Math.ceil(req.rateLimit.resetTime - Date.now()) / 1000} seconds` });
      sendEmail('alert_mail', req.body.email, { message: 'You have hit the rate limit on this action. Please try again later.' });
    } else {
      res.status(429).json({ success: false, error: `Rate limit exceeded, try again in ${Math.ceil(req.rateLimit.resetTime - Date.now()) / 1000} seconds` });
    }
  }
});

// Authentication endpoints
app.post('/api/affiliate/register', limiter, async (req, res) => {
  try {
    const { name, username, email, password, termsAccepted, recaptchaToken } = req.body;

    // Validation
    if (!name.match(/^[a-zA-Z\s]+\s+[a-zA-Z\s]+$/) || !username.match(/^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d]{5,}$/) || !email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/) || !password.match(/^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d]{8,}$/) || !termsAccepted) {
      return res.status(400).json({ success: false, error: 'Invalid input' });
    }

    const recaptchaRes = await fetch(`https://www.google.com/recaptcha/api/siteverify?secret=${process.env.CAPTCHA_SECRET_KEY}&response=${recaptchaToken}`, { method: 'POST' });
    const recaptchaData = await recaptchaRes.json();
    if (!recaptchaData.success) return res.status(400).json({ success: false, error: 'reCAPTCHA verification failed' });

    const { data: existingUser } = await supabase.from('users').select('email, username, status').or(`email.eq.${email},username.eq.${username}`).limit(1);
    if (existingUser?.length) {
      if (existingUser[0].status !== 'active') return res.status(400).json({ success: false, error: 'Account blocked or deleted' });
      if (existingUser[0].email === email) return res.status(400).json({ success: false, error: 'Email already exists' });
      if (existingUser[0].username === username) return res.status(400).json({ success: false, error: 'Username taken' });
    }

    const refCode = Math.random().toString(36).substring(2, 10).toUpperCase();
    const hashedPassword = await bcrypt.hash(password, 10);
    await redisClient.setEx(`signup:${email}`, 300, JSON.stringify({ name, username, email, password: hashedPassword, refCode, status: 'pending' }));
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await redisClient.setEx(`otp:signup:${email}`, 300, otp);
    await sendEmail('signup_mail', email, { name, otp });

    await redisClient.incr(`rate:signup:${email}`);
    await redisClient.expire(`rate:signup:${email}`, 600);
    res.status(200).json({ success: true, message: 'Verify your email' });
  } catch (err) {
    console.error('Register endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/affiliate/login', limiter, async (req, res) => {
  try {
    const { email, password, recaptchaToken } = req.body;

    const recaptchaRes = await fetch(`https://www.google.com/recaptcha/api/siteverify?secret=${process.env.CAPTCHA_SECRET_KEY}&response=${recaptchaToken}`, { method: 'POST' });
    const recaptchaData = await recaptchaRes.json();
    if (!recaptchaData.success) return res.status(400).json({ success: false, error: 'reCAPTCHA verification failed' });

    const { data: user, error } = await supabase.from('users').select('email, name, password, status').eq('email', email).single();
    if (error || !user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ success: false, error: 'Invalid credentials' });
    if (user.status !== 'active') return res.status(401).json({ success: false, error: user.status === 'blocked' ? 'Account suspended' : 'This email cannot create account' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await redisClient.setEx(`otp:login:${email}`, 300, otp);
    await sendEmail('login_mail', email, { name: user.name, otp });

    await redisClient.incr(`rate:login:${email}`);
    await redisClient.expire(`rate:login:${email}`, 600);
    res.status(200).json({ success: true, message: 'Verify your login' });
  } catch (err) {
    console.error('Login endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/affiliate/reset-password', limiter, async (req, res) => {
  try {
    const { email, recaptchaToken } = req.body;

    const recaptchaRes = await fetch(`https://www.google.com/recaptcha/api/siteverify?secret=${process.env.CAPTCHA_SECRET_KEY}&response=${recaptchaToken}`, { method: 'POST' });
    const recaptchaData = await recaptchaRes.json();
    if (!recaptchaData.success) return res.status(400).json({ success: false, error: 'reCAPTCHA verification failed' });

    const { data: user } = await supabase.from('users').select('email').eq('email', email).single();
    if (!user) return res.status(400).json({ success: false, error: 'Email not found' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await redisClient.setEx(`otp:reset:${email}`, 300, otp);
    await sendEmail('password_reset_mail', email, { name: cachedData.users.find(u => u.email === email)?.name || 'User', otp });

    await redisClient.incr(`rate:reset:${email}`);
    await redisClient.expire(`rate:reset:${email}`, 600);
    res.status(200).json({ success: true, message: 'Verify your email' });
  } catch (err) {
    console.error('Reset password endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/affiliate/verify-signup-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const storedOtp = await redisClient.get(`otp:signup:${email}`);
    if (!storedOtp || storedOtp !== otp) return res.status(400).json({ success: false, error: 'OTP expired or invalid, start over' });

    const signupData = JSON.parse(await redisClient.get(`signup:${email}`));
    const { error } = await supabase.from('users').insert({
      name: signupData.name,
      username: signupData.username,
      email: signupData.email,
      password: signupData.password,
      refCode: signupData.refCode,
      status: 'active',
      joinDate: new Date().toISOString(),
      linkClicks: 0,
      totalSales: 0,
      totalSalesMonthly: 0,
      currentBalance: 0,
      withdrawnTotal: 0
    });
    if (error) {
      console.error('Supabase insert error during signup:', error.message);
      return res.status(500).json({ success: false, error: 'Failed to create account' });
    }
    await Promise.all([
      redisClient.del(`signup:${email}`),
      redisClient.del(`otp:signup:${email}`)
    ]);
    await sendEmail('signup_mail', email, { name: signupData.name, message: 'Welcome to Deriv Bot Store Affiliates' });

    const token = jwt.sign({ email: signupData.email }, process.env.JWT_SECRET_SUPABASE, { expiresIn: '7d' });
    wsClients.set(signupData.email, { ws: null, role: 'affiliate' });
    res.status(200).json({ success: true, token, data: { name: signupData.name, username: signupData.username, refCode: signupData.refCode } });
  } catch (err) {
    console.error('Verify signup OTP endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/affiliate/verify-login-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const storedOtp = await redisClient.get(`otp:login:${email}`);
    if (!storedOtp || storedOtp !== otp) return res.status(400).json({ success: false, error: 'OTP expired or invalid, start over' });

    const { data: user } = await supabase.from('users').select('name, username, refCode, currentBalance, linkClicks, totalSales, totalSalesMonthly, withdrawnTotal').eq('email', email).single();
    if (!user) return res.status(400).json({ success: false, error: 'User not found' });
    const token = jwt.sign({ email }, process.env.JWT_SECRET_SUPABASE, { expiresIn: '7d' });
    res.status(200).json({ success: true, token, data: user });
  } catch (err) {
    console.error('Verify login OTP endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/affiliate/verify-reset-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const storedOtp = await redisClient.get(`otp:reset:${email}`);
    if (!storedOtp || storedOtp !== otp) return res.status(400).json({ success: false, error: 'OTP expired or invalid, start over' });

    res.status(200).json({ success: true, message: 'Set new password' });
  } catch (err) {
    console.error('Verify reset OTP endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/affiliate/set-new-password', async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    if (!newPassword.match(/^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d]{8,}$/)) {
      return res.status(400).json({ success: false, error: 'Invalid password format' });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const { error } = await supabase.from('users').update({ password: hashedPassword }).eq('email', email);
    if (error) {
      console.error('Supabase update error during password reset:', error.message);
      return res.status(500).json({ success: false, error: 'Failed to update password' });
    }
    for (const [clientEmail, client] of wsClients.entries()) {
      if (clientEmail === email && client.ws) {
        client.ws.send(JSON.stringify({ type: 'logout' }));
      }
    }
    await sendEmail('alert_mail', email, { message: 'Your password was changed. <a href="https://affiliate-botblitz.onrender.com/affiliate#forgot-password">Reset again</a>' });
    await redisClient.del(`otp:reset:${email}`);
    res.status(200).json({ success: true, message: 'Password reset, please login' });
  } catch (err) {
    console.error('Set new password endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/api/affiliate/data', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET_SUPABASE);
    const { data: user, error: userError } = await supabase.from('users').select('*').eq('email', decoded.email).single();
    if (userError || !user) {
      console.error('Supabase user fetch error:', userError?.message);
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    const { data: leaderboard, error: leaderboardError } = await supabase.from('users').select('name, totalSalesMonthly').order('totalSalesMonthly', { ascending: false }).limit(10);
    if (leaderboardError) console.error('Supabase leaderboard fetch error:', leaderboardError.message);

    const { data: history, error: historyError } = await supabase.from('history').select('*').eq('email', decoded.email).order('timestamp', { ascending: false }).limit(20);
    if (historyError) console.error('Supabase history fetch error:', historyError.message);

    const withdrawals = history ? history.filter(h => h.eventType === 'withdrawal') : [];
    const rewards = history ? history.filter(h => h.eventType === 'reward') : [];
    const notifications = history ? history.filter(h => h.eventType === 'notification') : [];

    res.status(200).json({ 
      success: true, 
      data: { 
        user, 
        withdrawals, 
        rewards, 
        notifications, 
        leaderboard: leaderboard || [], 
        news: cachedData.news, 
        forums: cachedData.forums,
        commissionRate: cachedData.settings.find(s => s.key === 'commissionRate')?.value || 0.2,
        rewardRate: cachedData.settings.find(s => s.key === 'rewardRate')?.value || 0.2
      } 
    });
  } catch (err) {
    console.error('Get affiliate data endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/api/admin/affiliate/affiliates', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET_SUPABASE);
    if (!decoded || decoded.role !== 'admin') return res.status(403).json({ success: false, error: 'Forbidden' });

    const { data, error } = await supabase.from('users').select('*');
    if (error) {
      console.error('Supabase affiliates fetch error:', error.message);
      return res.status(500).json({ success: false, error: 'Failed to fetch affiliates' });
    }
    res.status(200).json({ success: true, affiliates: data || [] });
  } catch (err) {
    console.error('Get affiliates endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/affiliate/track-click', cors(), async (req, res) => {
  try {
    const { affiliateref } = req.body;
    const { data: user, error } = await supabase.from('users').select('email, linkClicks').eq('refCode', affiliateref).single();
    if (error || !user) {
      console.error('Supabase user fetch error for track-click:', error?.message);
      return res.status(400).json({ success: false, error: 'Invalid referral code' });
    }
    const { error: updateError } = await supabase.from('users').update({ linkClicks: user.linkClicks + 1 }).eq('email', user.email);
    if (updateError) console.error('Supabase update error for track-click:', updateError.message);
    wsClients.get(user.email)?.ws?.send(JSON.stringify({ type: 'update' }));
    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Track click endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/affiliate/confirmed-sale', async (req, res) => {
  try {
    const { affiliateref, amount, item, apiKey } = req.body;
    if (apiKey !== process.env.API_KEY) return res.status(401).json({ success: false, error: 'Invalid API key' });
    const { data: user, error } = await supabase.from('users').select('*').eq('refCode', affiliateref).single();
    if (error || !user) {
      console.error('Supabase user fetch error for confirmed-sale:', error?.message);
      return res.status(400).json({ success: false, error: 'Invalid referral code' });
    }
    const commission = amount * (cachedData.settings.find(s => s.key === 'commissionRate')?.value || 0.2);
    const { error: updateError } = await supabase.from('users').update({
      totalSales: supabase.sql`totalSales + ${amount}`,
      totalSalesMonthly: supabase.sql`totalSalesMonthly + ${amount}`,
      currentBalance: supabase.sql`currentBalance + ${commission}`
    }).eq('email', user.email);
    if (updateError) console.error('Supabase update error for confirmed-sale:', updateError.message);
    const { error: historyError } = await supabase.from('history').insert({ email: user.email, eventType: 'sale', data: { amount, item, commission } });
    if (historyError) console.error('Supabase history insert error for confirmed-sale:', historyError.message);
    wsClients.get(user.email)?.ws?.send(JSON.stringify({ type: 'update' }));
    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Confirmed sale endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/affiliate/request-withdrawal-otp', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET_SUPABASE);
    const { amount, mpesaNumber, mpesaName, reuseDetails } = req.body;

    if (!amount || amount <= 0 || !mpesaNumber.match(/^0[17]\d{8}$/) || !mpesaName.match(/^[a-zA-Z\s]+\s+[a-zA-Z\s]+$/)) {
      return res.status(400).json({ success: false, error: 'Invalid input' });
    }

    const { data: user, error } = await supabase.from('users').select('currentBalance, email, name').eq('email', decoded.email).single();
    if (error || !user) {
      console.error('Supabase user fetch error for withdrawal:', error?.message);
      return res.status(401).json({ success: false, error: 'User not found' });
    }
    if (user.currentBalance < amount) return res.status(400).json({ success: false, error: 'Insufficient balance' });

    await redisClient.setEx(`withdrawal:${decoded.email}`, 300, JSON.stringify({ amount, mpesaNumber, mpesaName, reuseDetails }));
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await redisClient.setEx(`otp:withdrawal:${decoded.email}`, 300, otp);
    await sendEmail('withdrawal_mail', decoded.email, { name: user.name, otp });
    res.status(200).json({ success: true, message: 'Verify your email' });
  } catch (err) {
    console.error('Request withdrawal OTP endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/affiliate/verify-withdrawal-otp', async (req, res) => {
  try {
    const { email, otp, amount, mpesaNumber, mpesaName, reuseDetails } = req.body;
    const storedOtp = await redisClient.get(`otp:withdrawal:${email}`);
    if (!storedOtp || storedOtp !== otp) return res.status(400).json({ success: false, error: 'OTP expired or invalid' });

    const withdrawalData = JSON.parse(await redisClient.get(`withdrawal:${email}`));
    const { error } = await supabase.from('users').update({ 
      currentBalance: supabase.sql`currentBalance - ${amount}`, 
      ...(reuseDetails && { mpesaNumber, mpesaName }) 
    }).eq('email', email);
    if (error) {
      console.error('Supabase update error during withdrawal:', error.message);
      return res.status(500).json({ success: false, error: 'Failed to process withdrawal' });
    }
    const { error: historyError } = await supabase.from('history').insert({ email, eventType: 'withdrawal', data: { amount, mpesaNumber, mpesaName, status: 'pending' } });
    if (historyError) console.error('Supabase history insert error for withdrawal:', historyError.message);
    await sendEmail('withdrawal_mail', email, { name: cachedData.users.find(u => u.email === email)?.name || 'User', message: 'Withdrawal request submitted' });
    await Promise.all([redisClient.del(`withdrawal:${email}`), redisClient.del(`otp:withdrawal:${email}`)]);
    wsClients.get(email)?.ws?.send(JSON.stringify({ type: 'update' }));
    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Verify withdrawal OTP endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/affiliate/rewards', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET_SUPABASE);
    if (!decoded || decoded.role !== 'admin') return res.status(403).json({ success: false, error: 'Forbidden' });

    const { data: leaderboard, error: leaderboardError } = await supabase.from('users').select('email, totalSalesMonthly').order('totalSalesMonthly', { ascending: false }).limit(10);
    if (leaderboardError) console.error('Supabase leaderboard fetch error:', leaderboardError.message);
    const rewardRate = cachedData.settings.find(s => s.key === 'rewardRate')?.value || 0.2;
    for (const affiliate of (leaderboard || [])) {
      const reward = affiliate.totalSalesMonthly * rewardRate;
      const { error: updateError } = await supabase.from('users').update({ currentBalance: supabase.sql`currentBalance + ${reward}` }).eq('email', affiliate.email);
      if (updateError) console.error('Supabase update error for rewards:', updateError.message);
      const { error: historyError } = await supabase.from('history').insert({ email: affiliate.email, eventType: 'reward', data: { amount: reward, type: 'leaderboard' } });
      if (historyError) console.error('Supabase history insert error for rewards:', historyError.message);
      await sendEmail('reward_mail', affiliate.email, { name: cachedData.users.find(u => u.email === affiliate.email)?.name || 'User', amount: reward });
      wsClients.get(affiliate.email)?.ws?.send(JSON.stringify({ type: 'notification', message: `You received ${reward} KES as a reward`, color: 'green' }));
    }
    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Rewards endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/api/affiliate/static-page/:slug', async (req, res) => {
  try {
    const page = cachedData.static_pages.find(p => p.slug === req.params.slug);
    if (!page) return res.status(404).json({ success: false, error: 'Page not found' });
    res.status(200).json({ success: true, data: page });
  } catch (err) {
    console.error('Get static page endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/affiliate/communication', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET_SUPABASE);
    if (!decoded || decoded.role !== 'admin') return res.status(403).json({ success: false, error: 'Forbidden' });

    const { type, message } = req.body;
    if (type === 'urgentPopup') {
      const { error } = await supabase.from('settings').update({ value: JSON.stringify({ message, enabled: true }) }).eq('key', 'urgentPopup');
      if (error) console.error('Supabase update error for urgentPopup:', error.message);
      for (const [email, client] of wsClients.entries()) {
        if (client.role === 'affiliate') {
          client.ws?.send(JSON.stringify({ type: 'notification', message, color: 'red', urgent: true }));
        }
      }
    } else if (type === 'news') {
      const { error } = await supabase.from('news').insert({ message: sanitizeHtml(message) });
      if (error) {
        console.error('Supabase insert error for news:', error.message);
        return res.status(500).json({ success: false, error: error.message });
      }
      for (const [email, client] of wsClients.entries()) {
        client.ws?.send(JSON.stringify({ type: 'update' }));
      }
    }
    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Communication endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/affiliate/update-password', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET_SUPABASE);
    const { currentPassword, newPassword } = req.body;

    const { data: user, error } = await supabase.from('users').select('password').eq('email', decoded.email).single();
    if (error || !user || !(await bcrypt.compare(currentPassword, user.password))) {
      console.error('Supabase user fetch or password compare error:', error?.message);
      return res.status(401).json({ success: false, error: 'Invalid password' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await redisClient.setEx(`otp:change-password:${decoded.email}`, 300, otp);
    await sendEmail('password_reset_mail', decoded.email, { name: cachedData.users.find(u => u.email === decoded.email)?.name || 'User', otp });
    res.status(200).json({ success: true, message: 'Verify your email' });
  } catch (err) {
    console.error('Update password endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/affiliate/delete-account', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET_SUPABASE);
    const { data: user, error } = await supabase.from('users').select('currentBalance, name').eq('email', decoded.email).single();
    if (error || !user) {
      console.error('Supabase user fetch error for delete-account:', error?.message);
      return res.status(401).json({ success: false, error: 'User not found' });
    }
    if (user.currentBalance > 0) return res.status(400).json({ success: false, error: 'Cannot delete account with balance' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await redisClient.setEx(`otp:delete:${decoded.email}`, 300, otp);
    await sendEmail('alert_mail', decoded.email, { name: user.name, message: 'Please verify your account deletion with this OTP:', otp });
    res.status(200).json({ success: true, message: 'Verify your email' });
  } catch (err) {
    console.error('Delete account endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/affiliate/verify-password-otp', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    const storedOtp = await redisClient.get(`otp:change-password:${email}`);
    if (!storedOtp || storedOtp !== otp) return res.status(400).json({ success: false, error: 'OTP expired or invalid' });

    if (!newPassword.match(/^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d]{8,}$/)) {
      return res.status(400).json({ success: false, error: 'Invalid password format' });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const { error } = await supabase.from('users').update({ password: hashedPassword }).eq('email', email);
    if (error) {
      console.error('Supabase update error during password change:', error.message);
      return res.status(500).json({ success: false, error: 'Failed to update password' });
    }
    for (const [clientEmail, client] of wsClients.entries()) {
      if (clientEmail === email && client.ws) {
        client.ws.send(JSON.stringify({ type: 'logout' }));
      }
    }
    await sendEmail('alert_mail', email, { message: 'Your password was changed' });
    await redisClient.del(`otp:change-password:${email}`);
    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Verify password OTP endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/affiliate/verify-delete-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const storedOtp = await redisClient.get(`otp:delete:${email}`);
    if (!storedOtp || storedOtp !== otp) return res.status(400).json({ success: false, error: 'OTP expired or invalid' });

    const { error } = await supabase.from('users').update({ status: 'deleted' }).eq('email', email);
    if (error) {
      console.error('Supabase update error during account deletion:', error.message);
      return res.status(500).json({ success: false, error: 'Failed to delete account' });
    }
    for (const [clientEmail, client] of wsClients.entries()) {
      if (clientEmail === email && client.ws) {
        client.ws.send(JSON.stringify({ type: 'logout' }));
      }
    }
    await sendEmail('alert_mail', email, { message: 'Your account has been deleted' });
    await redisClient.del(`otp:delete:${email}`);
    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Verify delete OTP endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Health check endpoint for monitoring
app.get('/api/health', (req, res) => {
  res.status(200).json({ success: true, message: 'Server is running', timestamp: new Date().toISOString() });
});

// Logout endpoint to clean up WebSocket connections
app.post('/api/affiliate/logout', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET_SUPABASE);
    
    if (wsClients.has(decoded.email)) {
      const client = wsClients.get(decoded.email);
      if (client.ws) {
        client.ws.send(JSON.stringify({ type: 'logout' }));
        client.ws.close();
      }
      wsClients.delete(decoded.email);
    }
    
    res.status(200).json({ success: true, message: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout endpoint error:', err.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Error handling middleware for uncaught errors
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('Received SIGTERM, shutting down gracefully...');
  try {
    await redisClient.quit();
    console.log('Redis connection closed');
    server.close(() => {
      console.log('Express server closed');
      process.exit(0);
    });
  } catch (err) {
    console.error('Error during shutdown:', err.message);
    process.exit(1);
  }
});
