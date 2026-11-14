# Mutah Hash

Mutah Hash is a mobile-first virtual rewards web app. It is **not Bitcoin mining**: the HASH balance is a virtual programme balance, not BTC mined by a phone or held on a blockchain. All withdrawals are manual and subject to admin review; a displayed balance is not a promise of payment.

## Architecture

- Frontend: React + Vite, built to `dist/`.
- Authentication: Firebase Authentication (Email/Password), Firebase project `mutah-hash`.
- API: Cloudflare Worker in `worker/src/index.ts`.
- Database: Cloudflare D1 database `mutah-hash-prod`.
- Hosting target: Cloudflare Pages, connected to this GitHub repository.
- GitHub Actions: frontend build and Wrangler dry-run checks on pushes and pull requests.

## Business rules implemented in the API

- Activation is KSh 100 through Paystack Kenya M-Pesa.
- Activation is granted only after a signed Paystack webhook or server-side verification confirms the exact reference, KES 10,000 minor units, successful status, and matching user metadata.
- A second payment prompt is blocked while an earlier request is pending. Requests older than three minutes are verified before a retry is allowed.
- A successful eligible referral activation credits the referrer **USD 7.00 in virtual referral credit** (700 cents), once only.
- HASH sessions last 24 hours. A completed session credits 1,500 sats-equivalent virtual units (0.000015 virtual BTC units) once only.
- The 72-hour inactivity reset applies only to unreserved virtual HASH balance; pending/approved withdrawal amounts remain reserved.
- Withdrawal requests reserve available balance. Members can choose BSC (BNB Smart Chain/BEP20), SEGWITBTC (BTC SegWit), BTC (Bitcoin), or ETH (Ethereum/ERC20). Lightning Network is shown as suspended and is rejected by the API. The app records the selected network and shows request history. Admin approval/rejection and manual-paid recording are server-side and idempotent; no automatic transfer is made.
- The five-month withdrawal schedule mentioned in the original product discussion is not yet enforced because its exact timing and eligibility rules have not been confirmed.

## Admin access

The configured admin email is `johnmutahi44@gmail.com`.

1. Sign in to the app using that Firebase email account.
2. Open the **Admin** tab.
3. Select **Refresh admin data** to load member, payment, and withdrawal records.
4. Approve or reject pending withdrawal requests.
5. Only after you have actually sent a manual payout, select **Mark as manually paid**. This records the payout and deducts the reserved balance.

The Worker checks the signed Firebase ID token and compares its email to the server-side `ADMIN_EMAIL` setting. Hiding the Admin tab in the browser is not the security boundary.

## Required Worker settings

Set these in Cloudflare Worker settings; do not commit secret values:

- Variable: `FIREBASE_PROJECT_ID=mutah-hash`
- Variable: `ADMIN_EMAIL=johnmutahi44@gmail.com`
- Secret: `PAYSTACK_SECRET_KEY`

Configure the Paystack webhook URL as:

`https://YOUR-WORKER-SUBDOMAIN.workers.dev/api/paystack/webhook`

Subscribe to the `charge.success` event. Keep the Paystack secret key out of GitHub and the frontend.

## Frontend build settings

Cloudflare Pages build command: `npm run build`

Build output directory: `dist`

Set these Pages environment variables:

- `VITE_FIREBASE_API_KEY`
- `VITE_FIREBASE_AUTH_DOMAIN=mutah-hash.firebaseapp.com`
- `VITE_FIREBASE_PROJECT_ID=mutah-hash`
- `VITE_FIREBASE_APP_ID`
- `VITE_API_BASE_URL=https://YOUR-WORKER-SUBDOMAIN.workers.dev`

The Firebase web API key is client configuration, not a service-account key. Restrict its allowed domains after Pages deployment.

## Deployment and testing status

The repository and D1 schema are prepared, but this project is **not yet deployed or production-verified**. Do not use live customer payments until the Worker secret, webhook URL, Pages environment variables, and Paystack live configuration are set and end-to-end tests pass. Keep the previous AppDeploy site available until migration and data reconciliation are complete.

Before production:
- Run the GitHub Actions build.
- Deploy the Worker with the existing D1 binding.
- Deploy Pages and set its environment variables.
- Test Firebase registration/login and admin denial for a non-admin account.
- Test Paystack in test mode; verify duplicate webhook delivery does not double-activate or double-credit referrals.
- Test HASH start/claim at the 24-hour boundary and concurrent claim attempts.
- Test concurrent withdrawal submissions, approval, rejection, and manual-paid recording.
- Load-test expected traffic. 10,000 registered users is not the same as 10,000 simultaneous users.

## Local development

```bash
npm install
npm run dev
```
