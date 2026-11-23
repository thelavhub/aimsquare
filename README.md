# AIMsquare

- `backend/`  FastAPI server (accounts, saved projects, PDF OCR, exports, audit log, assistant). Hosted on Railway.
- `support-agent/`  The support agent definition (applied to your Anthropic account with the `ant` CLI; see its README).
- `web/`      The front-end site (`index.html`). Hosted on Vercel. `vercel.json` forwards `/api/*` to the Railway server.

Keep `backend/static/index.html` and `web/index.html` identical when you change the site.
Never put API keys or AIM_SECRET in any file here; they live in Railway Variables.
