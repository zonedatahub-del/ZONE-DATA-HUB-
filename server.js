const express = require('express');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const app = express();

const PORT = process.env.PORT || 3000;

// ===================== KEYS =====================
// Secret key is stored safely in Railway environment variables
// Never hardcoded — never visible in code or GitHub
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_WEBHOOK_SECRET = process.env.PAYSTACK_WEBHOOK_SECRET;

if (!PAYSTACK_SECRET_KEY) {
  console.error('❌ ERROR: PAYSTACK_SECRET_KEY is not set in environment variables!');
  process.exit(1);
}

// ===================== FRAUD PROTECTION STORE =====================
const usedReferences = new Set();
const ipAttempts = {};
const blockedIPs = new Set();

const MAX_ATTEMPTS_PER_IP = 5;
const BLOCK_DURATION_MS = 30 * 60 * 1000;

function trackIP(ip) {
  const now = Date.now();
  if (!ipAttempts[ip]) ipAttempts[ip] = { count: 0, firstAttempt: now };
  ipAttempts[ip].count += 1;

  if (now - ipAttempts[ip].firstAttempt > BLOCK_DURATION_MS) {
    ipAttempts[ip] = { count: 1, firstAttempt: now };
  }

  if (ipAttempts[ip].count >= MAX_ATTEMPTS_PER_IP) {
    blockedIPs.add(ip);
    console.warn(`🚨 FRAUD ALERT: IP ${ip} blocked after ${ipAttempts[ip].count} suspicious attempts.`);
    setTimeout(() => {
      blockedIPs.delete(ip);
      delete ipAttempts[ip];
      console.log(`✅ IP ${ip} has been unblocked.`);
    }, BLOCK_DURATION_MS);
  }
}

function fraudGuard(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  if (blockedIPs.has(ip)) {
    console.warn(`🚫 Blocked request from flagged IP: ${ip}`);
    return res.status(403).json({ verified: false, message: 'Access denied due to suspicious activity.' });
  }
  next();
}

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'Zone Data Hub is live ✅' });
});

// ===================== VERIFY PAYSTACK PAYMENT =====================
app.post('/verify-payment', fraudGuard, (req, res) => {
  const { reference, expectedAmount } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  if (!reference) {
    trackIP(ip);
    return res.status(400).json({ verified: false, message: 'No payment reference provided.' });
  }

  if (usedReferences.has(reference)) {
    trackIP(ip);
    console.warn(`🚨 FRAUD: Duplicate reference attempted: ${reference} from IP ${ip}`);
    return res.status(400).json({ verified: false, message: 'This payment reference has already been used.' });
  }

  const options = {
    hostname: 'api.paystack.co',
    port: 443,
    path: `/transaction/verify/${reference}`,
    method: 'GET',
    headers: {
      Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`
    }
  };

  const paystackReq = https.request(options, (paystackRes) => {
    let data = '';
    paystackRes.on('data', chunk => data += chunk);
    paystackRes.on('end', () => {
      try {
        const parsed = JSON.parse(data);

        if (!parsed.data || parsed.data.status !== 'success') {
          trackIP(ip);
          console.warn(`🚨 FRAUD: Failed payment attempt. Reference: ${reference}, IP: ${ip}`);
          return res.json({ verified: false, message: 'Payment was not successful.' });
        }

        const paidAmount = parsed.data.amount / 100;

        if (expectedAmount && Math.abs(paidAmount - expectedAmount) > 0.01) {
          trackIP(ip);
          console.warn(`🚨 FRAUD: Amount mismatch! Expected GH₵${expectedAmount}, got GH₵${paidAmount}. IP: ${ip}`);
          return res.json({ verified: false, message: 'Payment amount mismatch. Transaction blocked.' });
        }

        if (parsed.data.currency !== 'GHS') {
          trackIP(ip);
          console.warn(`🚨 FRAUD: Wrong currency: ${parsed.data.currency}. IP: ${ip}`);
          return res.json({ verified: false, message: 'Invalid payment currency.' });
        }

        usedReferences.add(reference);
        console.log(`✅ Payment verified: GH₵${paidAmount} | Ref: ${reference} | IP: ${ip}`);
        res.json({
          verified: true,
          amount: paidAmount,
          reference: parsed.data.reference,
          email: parsed.data.customer.email
        });

      } catch (e) {
        res.status(500).json({ verified: false, message: 'Error processing payment verification.' });
      }
    });
  });

  paystackReq.on('error', () => {
    res.status(500).json({ verified: false, message: 'Could not reach Paystack servers.' });
  });

  paystackReq.end();
});

// ===================== PAYSTACK WEBHOOK =====================
app.post('/webhook/paystack', express.raw({ type: 'application/json' }), (req, res) => {
  const hash = crypto
    .createHmac('sha512', PAYSTACK_WEBHOOK_SECRET || PAYSTACK_SECRET_KEY)
    .update(req.body)
    .digest('hex');

  if (hash !== req.headers['x-paystack-signature']) {
    console.warn('🚨 FRAUD: Invalid webhook signature detected.');
    return res.status(401).send('Unauthorized');
  }

  const event = JSON.parse(req.body);
  if (event.event === 'charge.success') {
    console.log(`🔔 Webhook confirmed: ${event.data.reference} | GH₵${event.data.amount / 100}`);
  }

  res.sendStatus(200);
});

app.listen(PORT, () => {
  console.log(`🚀 Zone Data Hub running on port ${PORT}`);
  console.log(`🔒 Fraud protection: ACTIVE`);
  console.log(`🔑 Secret key: loaded from environment ✅`);
});
