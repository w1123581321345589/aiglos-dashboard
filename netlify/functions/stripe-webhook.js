// netlify/functions/stripe-webhook.js
// Handles POST /api/stripe-webhook
// Listens for Stripe events and issues API keys on successful subscription creation.
//
// Stripe dashboard: Developers → Webhooks → Add endpoint
//   URL: https://aiglos.dev/api/stripe-webhook
//   Events to listen for:
//     checkout.session.completed
//     customer.subscription.deleted
//     invoice.payment_failed
//
// Set AIGLOS_WEBHOOK_SECRET from the signing secret shown in the webhook dashboard.

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const crypto = require('crypto');

// ── Key generation ──────────────────────────────────────────────────────────
// In production, replace with your key store (DynamoDB, Supabase, Redis, etc.)
// This version writes to a simple JSON log — works for early launch.

function generateApiKey() {
  return 'ak_live_' + crypto.randomBytes(24).toString('base64url');
}

async function issueApiKey(customerEmail, customerId, subscriptionId) {
  const apiKey = generateApiKey();

  // TODO: Store key in your database (DynamoDB, Supabase, PlanetScale, etc.)
  // Example Supabase call:
  //   await supabase.from('api_keys').insert({
  //     key: apiKey,
  //     customer_email: customerEmail,
  //     customer_id: customerId,
  //     subscription_id: subscriptionId,
  //     created_at: new Date().toISOString(),
  //     status: 'active',
  //   })

  console.log(`[Aiglos] API key issued for ${customerEmail}: ${apiKey.slice(0, 16)}...`);

  // Send welcome email with API key
  await sendWelcomeEmail(customerEmail, apiKey);

  return apiKey;
}

async function sendWelcomeEmail(email, apiKey) {
  // Replace with your email provider (Postmark, SendGrid, Resend, etc.)
  // Example using Resend:
  //
  // const resend = new Resend(process.env.RESEND_API_KEY);
  // await resend.emails.send({
  //   from: 'Aiglos <no-reply@aiglos.dev>',
  //   to: email,
  //   subject: 'Your Aiglos API key',
  //   html: emailTemplate(apiKey),
  // });

  const body = `
Your Aiglos API key is ready.

  AIGLOS_KEY=${apiKey}

Quick start:

  pip install aiglos
  export AIGLOS_KEY=${apiKey}

  # In your agent code — one line:
  import aiglos

  # That's it. Every MCP tool call is now protected.

Documentation: https://aiglos.dev/docs
Support: security@aiglos.dev

-- The Aiglos team
  `.trim();

  // Log for now — wire up Postmark/Resend/SendGrid before launch
  console.log(`[Aiglos] Would send to ${email}:\n${body}`);
}

// ── Webhook handler ──────────────────────────────────────────────────────────
exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  const sig = event.headers['stripe-signature'];
  let stripeEvent;

  try {
    stripeEvent = stripe.webhooks.constructEvent(
      event.body,
      sig,
      process.env.AIGLOS_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('[Aiglos] Webhook signature verification failed:', err.message);
    return { statusCode: 400, body: `Webhook Error: ${err.message}` };
  }

  console.log(`[Aiglos] Webhook event: ${stripeEvent.type}`);

  switch (stripeEvent.type) {
    case 'checkout.session.completed': {
      const session = stripeEvent.data.object;
      const email = session.customer_details?.email || session.metadata?.email;
      const customerId = session.customer;
      const subscriptionId = session.subscription;

      if (email && subscriptionId) {
        await issueApiKey(email, customerId, subscriptionId);
      }
      break;
    }

    case 'customer.subscription.deleted': {
      const sub = stripeEvent.data.object;
      // TODO: Revoke the API key associated with this subscription
      console.log(`[Aiglos] Subscription cancelled: ${sub.id}`);
      break;
    }

    case 'invoice.payment_failed': {
      const invoice = stripeEvent.data.object;
      // TODO: Notify customer, optionally throttle key
      console.log(`[Aiglos] Payment failed for customer: ${invoice.customer}`);
      break;
    }
  }

  return { statusCode: 200, body: JSON.stringify({ received: true }) };
};
