// netlify/functions/signup.js
// Handles POST /api/signup
// Free tier signups — no Stripe, just capture email and send onboarding.

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json',
  };

  try {
    const { email, name, plan } = JSON.parse(event.body || '{}');
    if (!email) return { statusCode: 400, headers, body: JSON.stringify({ error: 'Email required' }) };

    // TODO: Add to mailing list (Loops.so, ConvertKit, Beehiiv, etc.)
    // Free-tier users get the quick-start guide — nurture toward paid upgrade.

    console.log(`[Aiglos] Free signup: ${email} (${name || 'no name'})`);

    const gettingStarted = `
Hi ${name || 'there'},

Welcome to Aiglos. You're on the free tier — 10,000 tool calls/month, no API key required.

Quick start:

  pip install aiglos

  # In your agent:
  import aiglos  # zero-config, free tier active

That's it. Every MCP tool call is now scanned against 10 threat rule families.

When you're ready to unlock cloud telemetry, attestation artifacts, and compliance reports:
  https://aiglos.dev/#pricing

Questions: security@aiglos.dev

-- The Aiglos team
    `.trim();

    console.log(`[Aiglos] Would send to ${email}:\n${gettingStarted}`);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ success: true }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
