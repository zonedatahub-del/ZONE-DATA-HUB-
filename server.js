const express  = require('express');
const path     = require('path');
const https    = require('https');
const crypto   = require('crypto');
const app      = express();
const PORT     = process.env.PORT || 3000;

// ─────────────────────────────────────────────────────────────
// ENV KEYS (set all of these in Railway → Variables)
// ─────────────────────────────────────────────────────────────
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY;
if (!PAYSTACK_SECRET) {
  console.error('❌ PAYSTACK_SECRET_KEY not set in Railway Variables!');
  process.exit(1);
}

// Firebase Admin SDK — for server-side Firestore writes (refunds)
// Set FIREBASE_SERVICE_ACCOUNT in Railway as the full JSON string
// of your Firebase service account key (from Firebase Console →
// Project Settings → Service Accounts → Generate new private key)
let adminDb = null;
try {
  const admin = require('firebase-admin');
  if (process.env.FIREBASE_SERVICE_ACCOUNT && !admin.apps.length) {
    const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({ credential: admin.credential.cert(sa) });
    adminDb = admin.firestore();
    console.log('✅ Firebase Admin SDK connected — refund handling active');
  } else if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
    console.warn('⚠️  FIREBASE_SERVICE_ACCOUNT not set — refund webhook will log only');
  }
} catch (e) {
  console.warn('⚠️  firebase-admin not installed — run: npm install firebase-admin');
}

// ─────────────────────────────────────────────────────────────
// FRAUD PROTECTION
// ─────────────────────────────────────────────────────────────
const usedRefs   = new Set();
const ipAttempts = {};
const blockedIPs = new Set();
const BLOCK_MS   = 30 * 60 * 1000;
const MAX_TRIES  = 5;

function trackIP(ip) {
  const now = Date.now();
  if (!ipAttempts[ip]) ipAttempts[ip] = { count: 0, first: now };
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
    return res.status(403).json({ verified: false, message: 'Blocked.' });
  next();
}

// ─────────────────────────────────────────────────────────────
// STATIC FILES
// ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────────────────────
// PAYSTACK WEBHOOK — must be registered BEFORE express.json()
//
// THE FIX: express.raw() keeps req.body as Buffer so crypto
// can hash it. express.json() would parse it into an Object
// and crypto.createHmac().update(Object) crashes with
// ERR_INVALID_ARG_TYPE (this was the original server crash).
//
// This webhook handles:
//   charge.success  — logs confirmed payment
//   refund.processed — deducts wallet + writes refund tx record
//     Only fires AFTER Paystack confirms money reached mobile money
//     This prevents premature wallet deduction on refund initiation
// ─────────────────────────────────────────────────────────────
app.post(
  '/webhook/paystack',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const sig     = req.headers['x-paystack-signature'];
    const rawBody = req.body; // Buffer ✅

    if (!sig) {
      console.warn('🚨 Webhook: missing signature');
      return res.status(401).send('Unauthorized');
    }

    const hash = crypto
      .createHmac('sha512', PAYSTACK_SECRET)
      .update(rawBody)  // Buffer — no crash ✅
      .digest('hex');

    if (hash !== sig) {
      console.warn('🚨 Webhook: invalid signature');
      return res.status(401).send('Unauthorized');
    }

    let event;
    try { event = JSON.parse(rawBody.toString()); }
    catch (e) { return res.status(400).send('Bad Request'); }

    // ── charge.success ────────────────────────────────────────
    if (event.event === 'charge.success') {
      const d = event.data;
      console.log(`🔔 Payment confirmed: ${d.reference} | GH₵${(d.amount/100).toFixed(2)} | ${d.customer.email}`);
      // Balance already updated client-side via FieldValue.increment
      // This is just a server-side confirmation log
    }

    // ── refund.processed ─────────────────────────────────────
    // Paystack fires this ONLY when the refund money has actually
    // been sent back to the customer's mobile money / card.
    // This is the correct time to deduct from the wallet.
    // "refund.pending" is NOT used — we only act on confirmed refunds.
    if (event.event === 'refund.processed') {
      const refund = event.data;
      const ref    = refund.transaction_reference || refund.reference;
      const amount = refund.amount / 100; // convert pesewas to GHS
      console.log(`💸 Refund processed: ${ref} | GH₵${amount}`);

      if (adminDb) {
        try {
          // Find the transaction by Paystack reference
          // Searches the transactions sub-collection across all users
          const txSnap = await adminDb.collectionGroup('transactions')
            .where('ref', '==', ref)
            .limit(1)
            .get();

          if (!txSnap.empty) {
            const txDoc    = txSnap.docs[0];
            const uid      = txDoc.ref.parent.parent.id;
            const now      = new Date();
            const uRef     = adminDb.collection('users').doc(uid);
            const admin    = require('firebase-admin');
            const batch    = adminDb.batch();

            // Deduct refunded amount from wallet ONLY now that money
            // has confirmed reaching the customer's mobile money
            batch.update(uRef, {
              walletBalance: admin.firestore.FieldValue.increment(-amount)
            });

            // Write refund transaction record — shows in transaction history
            const refundTxRef = uRef.collection('transactions').doc(`TX-REFUND-${Date.now()}`);
            batch.set(refundTxRef, {
              type:        'Refund',
              amount:      -amount,
              description: `Refund processed by admin (original ref: ${ref})`,
              ref:         ref,
              date:        now.toLocaleDateString('en-GH', { day:'2-digit', month:'short', year:'numeric' }),
              time:        now.toLocaleTimeString('en-GH', { hour:'2-digit', minute:'2-digit' }),
              createdAt:   admin.firestore.FieldValue.serverTimestamp()
            });

            await batch.commit();
            console.log(`✅ Wallet deducted GH₵${amount} for UID: ${uid} | Refund TX written`);
          } else {
            console.warn(`⚠️  Refund ref ${ref} not found in any user's transactions`);
          }
        } catch (err) {
          console.error('Refund processing error:', err.message);
        }
      } else {
        console.log(`ℹ️  Refund ${ref} received but Firebase Admin not configured — set FIREBASE_SERVICE_ACCOUNT in Railway`);
      }
    }

    res.sendStatus(200);
  }
);

// ─────────────────────────────────────────────────────────────
// JSON PARSING for all other routes
// ─────────────────────────────────────────────────────────────
app.use(express.json());

// ─────────────────────────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({
    status: 'Zone Data Hub is live ✅',
    time: new Date().toISOString(),
    firebase_admin: adminDb ? 'connected' : 'not configured'
  });
});

// ─────────────────────────────────────────────────────────────
// VERIFY PAYMENT — called by frontend after Paystack popup
// Verifies with Paystack API using SECRET key (never exposed to browser)
// Fraud checks run in parallel with verification for speed
// ─────────────────────────────────────────────────────────────
app.post('/verify-payment', fraudGuard, (req, res) => {
  const { reference, expectedAmount } = req.body;
  const ip = req.ip || req.socket.remoteAddress;

  if (!reference) {
    trackIP(ip);
    return res.status(400).json({ verified: false, message: 'No reference provided.' });
  }

  if (usedRefs.has(reference)) {
    trackIP(ip);
    console.warn(`🚨 DUPLICATE REF: ${reference} from ${ip}`);
    return res.status(400).json({ verified: false, message: 'Reference already used.' });
  }

  const options = {
    hostname: 'api.paystack.co',
    port: 443,
    path: `/transaction/verify/${encodeURIComponent(reference)}`,
    method: 'GET',
    headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` }
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

        const paidGHS = tx.amount / 100;

        // Amount tamper check (0.5-second fraud protection)
        if (expectedAmount && Math.abs(paidGHS - Number(expectedAmount)) > 0.01) {
          trackIP(ip);
          console.warn(`🚨 AMOUNT MISMATCH: expected ${expectedAmount}, got ${paidGHS}`);
          return res.json({ verified: false, message: 'Payment amount mismatch.' });
        }

        if (tx.currency !== 'GHS') {
          trackIP(ip);
          return res.json({ verified: false, message: 'Invalid currency.' });
        }

        usedRefs.add(reference);
        console.log(`✅ Verified: GH₵${paidGHS} | ${reference}`);
        res.json({ verified: true, amount: paidGHS, reference: tx.reference, email: tx.customer.email });

      } catch (e) {
        res.status(500).json({ verified: false, message: 'Error verifying payment.' });
      }
    });
  });

  psReq.on('error', err => {
    console.error('Paystack error:', err.message);
    res.status(500).json({ verified: false, message: 'Could not reach Paystack.' });
  });

  psReq.end();
});

// ─────────────────────────────────────────────────────────────
// CATCH-ALL → index.html
// ─────────────────────────────────────────────────────────────
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─────────────────────────────────────────────────────────────
// START
// ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Zone Data Hub running on port ${PORT}`);
  console.log(`🔒 Fraud protection: ACTIVE`);
  console.log(`🔑 PAYSTACK_SECRET_KEY: loaded ✅`);
});
