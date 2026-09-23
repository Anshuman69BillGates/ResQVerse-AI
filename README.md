# ResQVerse AI — Final V1

A student-built full-stack emergency and healthcare assistance prototype.

## Stack
- Frontend: HTML/CSS/JavaScript, Leaflet, QRious
- Backend: Node.js + Express
- Database: MongoDB Atlas (optional locally, recommended for deployment)
- Authentication: JWT in an HTTP-only cookie + bcrypt password hashing
- Medical profile protection: optional application-level AES-256-GCM encryption via `ENCRYPTION_KEY`
- AI: Gemini server-side integration
- Emergency alerts: WhatsApp Click-to-Chat with saved emergency contacts
- Nearby hospitals/pharmacies: OpenStreetMap/Overpass browser discovery

## Run locally
1. Install Node.js LTS.
2. Open a terminal in this folder.
3. Run `npm.cmd install` on Windows PowerShell if `npm` is blocked by execution policy.
4. Copy `.env.example` to `.env`.
5. For local testing, MongoDB/Gemini can be configured through `.env`. MongoDB is recommended for persistent user data.
6. Run `npm.cmd start`.
7. Open `http://localhost:3000`.

## Production configuration
Set these environment variables on the hosting platform:
- `MONGODB_URI`
- `JWT_SECRET`
- `ENCRYPTION_KEY`
- `GEMINI_API_KEY`
- `GEMINI_MODEL` (default `gemini-2.5-flash`)
- `COOKIE_SECURE=true`
- `NODE_ENV=production`

Never commit `.env` or API keys to GitHub.

## What is actually live in this V1
- Guest browsing
- ResQ account signup/login/logout
- ResQ ID generation after medical profile completion
- Profile persistence through MongoDB when configured
- Emergency contacts persistence when configured
- Server-side AI endpoint when Gemini is configured
- WhatsApp emergency alerts with the user's current location
- Direct India 112 call button in the browser
- Nearby hospitals and pharmacies through OpenStreetMap/Overpass
- Demo medicine-price comparison is explicitly labelled as demo data; it is not presented as live pharmacy inventory
- Medicine reminders use browser notifications while the page is open

## Safety / scope
This is a student-built prototype, not a certified medical device or emergency dispatch system. The app does not claim to diagnose users, dispatch ambulances, or provide verified live medicine prices. Emergency users should contact local emergency services immediately when appropriate.

## Deployment
The included `render.yaml` is a starting point for a Node web service. Configure the environment variables in the host dashboard, deploy, verify `/api/health`, then connect your custom domain.


## ResQ AI — one shared server-side Gemini key

ResQ AI is designed so visitors do **not** enter their own Gemini API key. The browser calls `/api/ai/chat`; the server reads `GEMINI_API_KEY` from its private environment and calls Gemini. Never place the real key in `public/index.html`, JavaScript source, GitHub, or a downloadable ZIP.

### Local setup
1. Copy `.env.example` to `.env`.
2. Set `GEMINI_API_KEY=...` in `.env`.
3. Keep `.env` private; `.gitignore` excludes it.
4. Restart the server with `npm.cmd start`.

### Deployment
Set `GEMINI_API_KEY` in the hosting provider's Environment Variables/Secrets. Do **not** commit `.env`. Every visitor can then use the same ResQ AI service through the backend, subject to your Gemini quota and the app's rate limit.

### Important
The server-side key is shared by the application, so monitor provider quota/costs and keep the AI endpoint rate-limited. A production launch should also add stronger abuse prevention, usage quotas, logging, and billing alerts.
