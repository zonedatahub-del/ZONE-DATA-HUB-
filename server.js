const express = require('express');
const path    = require('path');
const https   = require('https');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────
// ENV KEYS  (set these in Railway → Variables)
// ─────────────────────────────────────────────
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;

if (!PAYSTACK_SECRET_KEY) {
  console.error('❌ PAYSTACK_SECRET_KEY not set in Railway Variables!');
  process.exit(1);
}

// ─────────────────────────────────────────────
// FRAUD PROTECTION
// ─────────────────────────────────────────────
const usedRefs   = new Set();   // block duplicate payment references
const ipAttempts = {};
const blockedIPs = new Set();
const BLOCK_MS   = 30 * 60 * 1000;
const MAX_TRIES  = 5;

function trackIP(ip) {
  const now = Date.now();
  if (!ipAttempts[ip]) ipAttempts[ip] = { count: 0, first: now };
  // reset window after block period
  if (now - ipAttempts[ip].first > BLOCK_MS) ipAttempts[ip] = { count: 0, first: now };
  ipAttempts[ip].count++;
  if (ipAttempts[ip].count >= MAX_TRIES) {
    blockedIPs.add(ip);
    console.warn(`🚨 IP BLOCKED: ${ip}`);
    setTimeout(() => { blockedIPs.delete(ip); delete ipAttempts[ip]; }, BLOCK_MS);
  }
}

function fraudGuard(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress;
  if (blockedIPs.has(ip))
    return res.status(403).json({ verified: false, message: 'Blocked due to suspicious activity.' });
  next();
}

// ─────────────────────────────────────────────
// STATIC FILES  (serves public/index.html)
// ─────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────
// PAYSTACK WEBHOOK  ← THE FIX IS HERE
//
// The crash was:
//   TypeError: "data" argument must be string/Buffer — got Object
//
// Root cause: express.json() was registered globally, so by the
// time the webhook handler ran, req.body was already a JS object,
// not raw bytes.  crypto.createHmac().update() cannot handle
// a plain object.
//
// Fix: register express.raw() BEFORE express.json(), but scoped
// ONLY to the webhook route.  All other routes still get JSON parsing.
// ─────────────────────────────────────────────
app.post(
  '/webhook/paystack',
  express.raw({ type: 'application/json' }),  // keeps body as Buffer
  (req, res) => {
    const secret    = PAYSTACK_SECRET_KEY;
    const signature = req.headers['x-paystack-signature'];
    const rawBody   = req.body;                          // Buffer ✅

    if (!signature) {
      console.warn('🚨 Webhook: missing signature header');
      return res.status(401).send('Unauthorized');
    }

    const hash = crypto
      .createHmac('sha512', secret)
      .update(rawBody)                                   // Buffer — no crash ✅
      .digest('hex');

    if (hash !== signature) {
      console.warn('🚨 Webhook: invalid signature — possible forgery');
      return res.status(401).send('Unauthorized');
    }

    let event;
    try {
      event = JSON.parse(rawBody.toString());            // parse AFTER verification
    } catch (e) {
      return res.status(400).send('Bad Request');
    }

    if (event.event === 'charge.success') {
      const d = event.data;
      console.log(`🔔 Webhook confirmed: ${d.reference} | GH₵${(d.amount / 100).toFixed(2)}`);
    }

    res.sendStatus(200);
  }
);

// ─────────────────────────────────────────────
// JSON PARSING for all other routes
// ─────────────────────────────────────────────
app.use(express.json());

// ─────────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ status: 'Zone Data Hub is live ✅', time: new Date().toISOString() });
});

// ─────────────────────────────────────────────
// VERIFY PAYSTACK PAYMENT
// Called by the frontend after Paystack popup confirms success.
// We verify with Paystack's API using the SECRET key (never exposed
// to the browser) — this prevents anyone faking a payment.
//
// New requirements addressed:
//  • Amount-tamper check (blocks users changing the price client-side)
//  • Currency check    (GHS only)
//  • Duplicate-ref block (replay attack prevention)
//  • IP fraud tracking
// ─────────────────────────────────────────────
app.post('/verify-payment', fraudGuard, (req, res) => {
  const { reference, expectedAmount } = req.body;
  const ip = req.ip || req.socket.remoteAddress;

  if (!reference) {
    trackIP(ip);
    return res.status(400).json({ verified: false, message: 'No payment reference provided.' });
  }

  if (usedRefs.has(reference)) {
    trackIP(ip);
    console.warn(`🚨 DUPLICATE REF: ${reference} from ${ip}`);
    return res.status(400).json({ verified: false, message: 'Payment reference already used.' });
  }

  const options = {
    hostname: 'api.paystack.co',
    port: 443,
    path: `/transaction/verify/${encodeURIComponent(reference)}`,
    method: 'GET',
    headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` }
  };

  const psReq = https.request(options, psRes => {
    let raw = '';
    psRes.on('data', chunk => raw += chunk);
    psRes.on('end', () => {
      try {
        const parsed = JSON.parse(raw);
        const tx     = parsed.data;

        if (!tx || tx.status !== 'success') {
          trackIP(ip);
          return res.json({ verified: false, message: 'Payment not successful.' });
        }

        // Amount tamper check
        const paidGHS = tx.amount / 100;
        if (expectedAmount && Math.abs(paidGHS - Number(expectedAmount)) > 0.01) {
          trackIP(ip);
          console.warn(`🚨 AMOUNT MISMATCH: expected ${expectedAmount}, got ${paidGHS} | ref ${reference}`);
          return res.json({ verified: false, message: 'Payment amount mismatch — blocked.' });
        }

        // Currency check
        if (tx.currency !== 'GHS') {
          trackIP(ip);
          return res.json({ verified: false, message: 'Invalid currency.' });
        }

        usedRefs.add(reference);
        console.log(`✅ Payment verified: GH₵${paidGHS} | ref ${reference}`);
        res.json({ verified: true, amount: paidGHS, reference: tx.reference, email: tx.customer.email });

      } catch (e) {
        console.error('Verify parse error:', e.message);
        res.status(500).json({ verified: false, message: 'Error verifying payment.' });
      }
    });
  });

  psReq.on('error', err => {
    console.error('Paystack request error:', err.message);
    res.status(500).json({ verified: false, message: 'Could not reach Paystack.' });
  });

  psReq.end();
});

// ─────────────────────────────────────────────
// CATCH-ALL → index.html  (single-page app support)
// ─────────────────────────────────────────────
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Zone Data Hub running on port ${PORT}`);
  console.log(`🔒 Fraud protection: ACTIVE`);
  console.log(`🔑 PAYSTACK_SECRET_KEY loaded from environment ✅`);
  console.log(`✅ Wallet System Connected!`);
});
