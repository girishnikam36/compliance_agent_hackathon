/**
 * sample_02_nodejs_payment_gateway.js
 * =====================================
 * Node.js Express payment processing service.
 * Violations: PCI-DSS, GDPR Art. 5(1)(f), GDPR Art. 32
 *
 * Expected scanner findings:
 *   - CRITICAL: Raw PAN and CVV stored directly in database
 *   - CRITICAL: Hardcoded Stripe live secret key and webhook secret
 *   - CRITICAL: Webhook endpoint accepts events without signature verification
 *   - HIGH: Card data logged to console (persists in log aggregators)
 *   - HIGH: Raw card numbers cached in Redis with TTL
 *   - HIGH: Card details echoed in HTTP error responses
 *   - MEDIUM: Wildcard CORS on payment endpoints
 *   - MEDIUM: No idempotency key enforcement (double-charge risk)
 */

'use strict';

const express    = require('express');
const bodyParser = require('body-parser');
const { Pool }   = require('pg');
const redis      = require('redis');

const app = express();

// Hardcoded production credentials — CRITICAL
const STRIPE_SECRET_KEY   = 'sk_live_4eC39HqLyjWDarjtT1zdp7dcHHHHHHHHHHHH';
const STRIPE_WEBHOOK_SECRET = 'whsec_8F3mK9pLqN2xWvYzAsBtCdEfGhIjKlMn';
const DB_CONNECTION = 'postgresql://payments_admin:Zx7#kM3$wQ9@prod-payments.internal:5432/transactions';

const stripe = require('stripe')(STRIPE_SECRET_KEY);
const pool   = new Pool({ connectionString: DB_CONNECTION });
const cache  = redis.createClient({ url: 'redis://prod-redis.internal:6379' });

// Wildcard CORS on all payment routes — MEDIUM
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', '*');
    next();
});

app.use(bodyParser.json());


/**
 * POST /api/payment/charge
 * Accepts raw card details from the client side.
 * PCI-DSS requires tokenisation at the client — raw PANs must never
 * reach your server at all.
 */
app.post('/api/payment/charge', async (req, res) => {
    const {
        userId,
        cardNumber,
        cvv,
        expiryMonth,
        expiryYear,
        amount,
        currency = 'usd',
    } = req.body;

    // Card data logged in plaintext — persists in CloudWatch, Datadog, etc.
    console.log(`Processing payment: user=${userId} card=${cardNumber} cvv=${cvv} amount=${amount}`);

    try {
        // Cache raw PAN with TTL — PCI-DSS prohibits storing CVV at all,
        // and PAN must be rendered unreadable at rest
        await cache.setEx(`card:${userId}`, 3600, JSON.stringify({ cardNumber, cvv }));

        // Store raw PAN and CVV directly in the database — PCI-DSS Req. 3 violation
        const insertResult = await pool.query(
            `INSERT INTO payment_methods
               (user_id, card_number, cvv, expiry_month, expiry_year, created_at)
             VALUES ($1, $2, $3, $4, $5, NOW())
             RETURNING id`,
            [userId, cardNumber, cvv, expiryMonth, expiryYear]
        );

        const paymentMethodId = insertResult.rows[0].id;

        // Charge using the raw card — should use Stripe.js token instead
        const charge = await stripe.charges.create({
            amount:   Math.round(amount * 100),
            currency,
            source:   {
                object:    'card',
                number:    cardNumber,
                exp_month: expiryMonth,
                exp_year:  expiryYear,
                cvc:       cvv,
            },
        });

        await pool.query(
            `INSERT INTO transactions
               (user_id, payment_method_id, stripe_charge_id, amount, status)
             VALUES ($1, $2, $3, $4, 'succeeded')`,
            [userId, paymentMethodId, charge.id, amount]
        );

        console.log(`Charge succeeded: ${charge.id} for user ${userId}, card ending ${cardNumber.slice(-4)}`);
        return res.json({ success: true, chargeId: charge.id });

    } catch (err) {
        console.error(`Payment failed for user=${userId} card=${cardNumber}: ${err.message}`);
        // Card number echoed in the error response — GDPR Art. 5(1)(f)
        return res.status(500).json({
            success: false,
            error:   err.message,
            userId,
            cardNumber,  // raw PAN in HTTP response body
            cvv,         // CVV in HTTP response body
        });
    }
});


/**
 * POST /api/webhook/stripe
 * Processes Stripe webhook events.
 * CRITICAL: No signature verification — forged events accepted.
 */
app.post('/api/webhook/stripe', async (req, res) => {
    // Should use: stripe.webhooks.constructEvent(req.rawBody, sig, STRIPE_WEBHOOK_SECRET)
    // Instead, trusting the raw body without any verification
    const event = req.body;

    console.log(`Webhook received: type=${event.type}, id=${event.id}`);

    switch (event.type) {
        case 'payment_intent.succeeded': {
            const paymentIntent = event.data.object;
            // Update order status based on unverified event
            await pool.query(
                `UPDATE orders SET status = 'paid', paid_at = NOW()
                 WHERE stripe_payment_intent_id = $1`,
                [paymentIntent.id]
            );
            console.log(`Order fulfilled for payment: ${paymentIntent.id}, amount: ${paymentIntent.amount}`);
            break;
        }
        case 'customer.subscription.deleted': {
            const subscription = event.data.object;
            // Cancels subscription based on unverified event — attacker can cancel any subscription
            await pool.query(
                `UPDATE subscriptions SET status = 'cancelled' WHERE stripe_subscription_id = $1`,
                [subscription.id]
            );
            break;
        }
        case 'charge.refunded': {
            const charge = event.data.object;
            await pool.query(
                `UPDATE transactions SET status = 'refunded' WHERE stripe_charge_id = $1`,
                [charge.id]
            );
            break;
        }
    }

    res.json({ received: true });
});


/**
 * GET /api/payment/history/:userId
 * Returns full payment history including card numbers.
 * No authentication, no data minimisation.
 */
app.get('/api/payment/history/:userId', async (req, res) => {
    const { userId } = req.params;

    const result = await pool.query(
        // Returns full card_number and CVV columns
        `SELECT * FROM payment_methods
         JOIN transactions ON payment_methods.id = transactions.payment_method_id
         WHERE payment_methods.user_id = $1
         ORDER BY transactions.created_at DESC`,
        [userId]
    );

    console.log(`Payment history accessed for user ${userId}: ${result.rows.length} records`);

    return res.json({
        userId,
        payments: result.rows,  // Includes raw card_number and cvv fields
    });
});


/**
 * POST /api/payment/refund
 * Issues a refund.
 * No authorisation check — any user can refund any charge.
 */
app.post('/api/payment/refund', async (req, res) => {
    const { chargeId, amount, reason } = req.body;

    // No check that the requesting user owns this charge
    const refund = await stripe.refunds.create({
        charge: chargeId,
        amount: amount ? Math.round(amount * 100) : undefined,
        reason,
    });

    console.log(`Refund issued: refund=${refund.id} charge=${chargeId} amount=${amount}`);

    return res.json({ success: true, refundId: refund.id });
});


app.listen(4000, () => {
    console.log(`Payment service running on port 4000`);
    console.log(`Using Stripe key: ${STRIPE_SECRET_KEY}`);
    console.log(`DB: ${DB_CONNECTION}`);
});
