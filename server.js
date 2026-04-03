const express = require('express');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const admin = require('firebase-admin');
const cors = require('cors');
const app = express();

const PORT = process.env.PORT || 3000;

// === SAFE FIREBASE SETUP ===
let db = null;
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: process.env.FIREBASE_DATABASE_URL
    });
    db = admin.database();
    console.log("✅ Wallet System Connected!");
  } catch (err) {
    console.error("❌ Firebase Error:", err.message);
  }
}

// ===================== YOUR ORIGINAL SECURITY CODE =====================
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_WEBHOOK_SECRET = process.env.PAYSTACK_WEBHOOK_SECRET;

const usedReferences = new Set();
const ipAttempts = {};
const blockedIPs = new Set();

function trackIP(ip) {
  const now = Date.now();
  if (!ipAttempts[ip]) ipAttempts[ip] = { count: 0, firstAttempt: now };
  ipAttempts[ip].count += 1;
  if (ipAttempts[ip].count >= 5) blockedIPs.add(ip);
}

function fraudGuard(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  if (blockedIPs.has(ip)) return res.status(403).send('Blocked');
  next();
}

app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });
app.get('/health', (req, res) => { res.json({ status: 'Live ✅' }); });

// ===================== NEW: AI SUPPORT ISSUE WHATSAPP TRIGGER =====================
app.post('/report-issue', async (req, res) => {
  const { orderId, description } = req.body;
  if (!db) return res.status(500).send('Database not connected');

  try {
    // 1. Get Order Info from Firebase
    const orderSnap = await db.ref(`orders/${orderId}`).once('value');
    const orderData = orderSnap.val();

    if (!orderData) return res.status(404).json({ message: "Order ID not found" });

    // 2. Prepare the info for WhatsApp (Front-end will open the link)
    res.json({
      success: true,
      whatsappMessage: `⚠️ *Issue Reported*\n🆔 *Order ID:* ${orderId}\n📦 *Package:* ${orderData.packageName}\n🗓️ *Date:* ${orderData.date}\n📝 *Issue:* ${description}`,
      phones: ["233531861148", "233537172705"]
    });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// ===================== PAYSTACK VERIFY =====================
app.post('/verify-payment', fraudGuard, (req, res) => {
  const { reference } = req.body;
  const options = {
    hostname: 'api.paystack.co', port: 443, path: `/transaction/verify/${reference}`,
    method: 'GET', headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` }
  };
  const payReq = https.request(options, (pRes) => {
    let d = ''; pRes.on('data', c => d += c);
    pRes.on('end', () => { res.json(JSON.parse(d)); });
  });
  payReq.end();
});

// ===================== WEBHOOK (THE MONEY RECEIVER + NOTIFICATION LOG) =====================
app.post('/webhook/paystack', express.raw({ type: 'application/json' }), async (req, res) => {
  const hash = crypto.createHmac('sha512', PAYSTACK_WEBHOOK_SECRET || PAYSTACK_SECRET_KEY).update(req.body).digest('hex');
  if (hash !== req.headers['x-paystack-signature']) return res.sendStatus(401);

  const event = JSON.parse(req.body);
  if (event.event === 'charge.success' && db) {
    const { amount, metadata, reference, customer } = event.data;
    const userId = metadata ? metadata.user_id : null;
    const packageName = metadata ? metadata.package_name : "Top Up";
    const deposit = amount / 100;

    if (userId) {
      // 1. Add money to user's wallet
      await db.ref(`users/${userId}/wallet`).transaction(c => (c || 0) + deposit);
      
      // 2. Add to transaction history
      await db.ref(`transactions/${userId}`).push().set({
        type: "Top Up", amount: deposit, status: "Success", date: Date.now(), ref: reference
      });

      // 3. Log Order Details for WhatsApp (Ready for Frontend to trigger)
      console.log(`🚀 READY FOR WHATSAPP: GH₵${deposit} by ${customer.email} for ${packageName}`);
    }
  }
  res.sendStatus(200);
});

app.listen(PORT, () => { console.log(`🚀 Site running on port ${PORT}`); });
