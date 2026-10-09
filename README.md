# KMJ TIPS — Admin Panel + API

Activation-key management and app-update backend for the KMJ Android SDK.

- **Start:** `npm install && node bot.js` (or `npm start`)
- **First admin:** `node bot.js --setup`, or "First run? Create admin account" on the login page
- **Panel:** single self-contained `public/index.html`
- **Deploy:** Render Web Service, Build `npm install`, Start `npm start`, env `JWT_SECRET` (min 32 chars) + `TRUST_PROXY=1`
