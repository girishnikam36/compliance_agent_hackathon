/**
 * test_samples/sample_02_nodejs_payment_handler.js
 * ==================================================
 * EXPLOIT CATEGORY : Payment / PCI-DSS + GDPR Art. 5, 32
 * SEVERITY PROFILE : 3 CRITICAL · 2 HIGH
 * REGULATIONS      : GDPR, PCI-DSS, DPDPA
 * LANGUAGE         : JavaScript (Node.js / Express)
 *
 * What this file simulates:
 *   A Node.js Express payment processing route from an e-commerce backend.
 *   Contains the classic payment security failures seen in breach reports:
 *   - Raw card numbers stored in database
 *   - CVV persisted (explicitly forbidden by PCI-DSS)
 *   - Card data logged to stdout
 *   - Webhook secret hardcoded in source
 *   - No TLS enforcement check
 *
 * HOW TO TEST:
 *   Paste into the Oxbuild UI. The C++ scanner will redact:
 *     admin@payments.io     → [PII_EMAIL_xxxxxxxx]
 *     10.0.0.50             → [PII_IPV4_xxxxxxxx]
 *     whsec_abc123...       → [PII_API_KEY_xxxxxxxx]
 *   Expected violations: 5+
 */

const express = require('express');
const stripe  = require('stripe');
const db      = require('./db');
const router  = express.Router();

// ── EXPLOIT 1: Hardcoded secrets in source code ───────────────────────────────
// GDPR Art. 32 — Security of Processing
// PCI-DSS Req. 6.4 — Protect against known vulnerabilities
const STRIPE_SECRET      = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';
const WEBHOOK_SECRET     = 'whsec_abc123def456ghi789jkl012mno345pqr678';
const INTERNAL_API_URL   = 'http://10.0.0.50:3000/internal';
const PAYMENT_ADMIN      = 'admin@payments.io';

const stripeClient = stripe(STRIPE_SECRET);

// ── EXPLOIT 2: Raw card number stored in database ─────────────────────────────
// PCI-DSS Req. 3.2 — Do not store sensitive authentication data
// GDPR Art. 5(1)(f) — Integrity and Confidentiality
router.post('/charge', async (req, res) => {
  const { userId, cardNumber, cvv, expiryMonth, expiryYear, amount } = req.body;

  // Log card details to console — CRITICAL PCI-DSS violation
  console.log(`Processing payment for user ${userId}: card=${cardNumber} cvv=${cvv}`);

  // Store raw card number AND cvv in database — forbidden by PCI-DSS
  await db.query(
    `INSERT INTO payment_methods (user_id, card_number, cvv, expiry_month, expiry_year)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, cardNumber, cvv, expiryMonth, expiryYear]
  );

  // Charge via Stripe — this part is compliant, but the data above is not
  const charge = await stripeClient.charges.create({
    amount,
    currency: 'usd',
    source:   await stripeClient.tokens.create({
      card: { number: cardNumber, exp_month: expiryMonth, exp_year: expiryYear, cvc: cvv }
    }),
  });

  res.json({ success: true, chargeId: charge.id });
});

// ── EXPLOIT 3: Payment history returned with full card numbers ────────────────
// PCI-DSS Req. 3.3 — Mask PAN when displayed
// GDPR Art. 25 — Data Protection by Design
router.get('/history/:userId', async (req, res) => {
  const { userId } = req.params;

  // Returns card_number and cvv in the API response — CRITICAL
  const payments = await db.query(
    'SELECT * FROM payment_methods WHERE user_id = $1',
    [userId]
  );

  res.json({ payments: payments.rows });   // full card numbers in API response
});

// ── EXPLOIT 4: Webhook handler with no signature validation ──────────────────
// PCI-DSS Req. 6.4 — Input validation
// GDPR Art. 32 — Secure processing
router.post('/webhook', (req, res) => {
  const event = req.body;   // No stripe.webhooks.constructEvent() verification
  console.log('Webhook received:', JSON.stringify(event));   // logs full event body

  if (event.type === 'payment_intent.succeeded') {
    const paymentIntent = event.data.object;
    db.query(
      `UPDATE orders SET status='paid', payment_data=$1 WHERE stripe_id=$2`,
      [JSON.stringify(paymentIntent), paymentIntent.id]  // stores full payment object
    );
  }
  res.json({ received: true });
});

// ── EXPLOIT 5: Card details returned in error messages ───────────────────────
// GDPR Art. 32 — Data breach risk
router.use((err, req, res, next) => {
  console.error('Payment error:', err.message, 'Card:', req.body.cardNumber);
  res.status(500).json({ error: err.message, debug: { card: req.body.cardNumber } });
});

module.exports = router;
