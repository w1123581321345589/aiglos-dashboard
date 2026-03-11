# Launch checklist — live signups in ~5 minutes

## Step 1 — Stripe: create product and payment link

1. Go to [dashboard.stripe.com](https://dashboard.stripe.com)
2. Products → Add product → name it **"Aiglos Pro"**
3. Pricing: **Metered**, unit = "tool call", price = **$39**
4. Payment Links → Create link → select "Aiglos Pro"
5. Copy the Payment Link URL (looks like `https://buy.stripe.com/...`)
6. Settings → Developers → API keys → copy **Publishable key** (starts with `pk_live_...`)

## Step 2 — Wire into index.html

Open `index.html`. Find these two lines near the top (inside the `<script>` tag):

```js
const STRIPE_PAYG_PAYMENT_LINK = "STRIPE_PAYG_PAYMENT_LINK";
const STRIPE_PUBLISHABLE_KEY   = "STRIPE_PUBLISHABLE_KEY";
```

Replace with your actual values:

```js
const STRIPE_PAYG_PAYMENT_LINK = "https://buy.stripe.com/YOUR_LINK_HERE";
const STRIPE_PUBLISHABLE_KEY   = "pk_live_YOUR_KEY_HERE";
```

## Step 3 — Push to GitHub

```bash
git add index.html netlify.toml
git commit -m "wire stripe payment link"
git push
```

## Step 4 — Deploy on Netlify

1. [app.netlify.com](https://app.netlify.com) → Add new site → Import from GitHub
2. Select this repo
3. Build command: (leave empty)
4. Publish directory: `.`
5. Click Deploy

Netlify auto-detects `netlify.toml`. Deploy takes ~30 seconds.

## Step 5 — Verify

- Homepage loads at your Netlify URL
- "Get API key" and "Start free" buttons open the Stripe Payment Link
- `/scan` serves the ClawHub skill scanner
- `/docs` redirects to GitHub

That is it. Stripe handles checkout, receipts, and customer records.
You issue API keys manually until you wire the webhook (see below).

---

## When you are ready to automate key issuance (~15 min each)

### Resend (transactional email)
1. [resend.com](https://resend.com) → Get API key → paste into Netlify env vars as `RESEND_API_KEY`
2. The scaffolding is already in `netlify/functions/stripe-webhook.js`
3. Uncomment the `resend.emails.send()` block

### Supabase (key storage)
1. [supabase.com](https://supabase.com) → New project → copy URL and anon key
2. Add to Netlify env vars: `SUPABASE_URL` and `SUPABASE_ANON_KEY`
3. Run the migration in `netlify/functions/stripe-webhook.js` (comment block at top)
4. Uncomment the `supabase.from('customers').insert()` block

Both free tiers handle early scale without any changes.
