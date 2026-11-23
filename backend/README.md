# AIMsquare backend

FastAPI + SQLite. Adds to the AIMsquare site: accounts, saved projects, server-side PDF reading (with OCR for scanned pages), a hash-chained audit log, and Word/PDF report export. The page still works on its own (browser-only) when no backend is reachable.

## Run locally
    pip install -r requirements.txt
    sudo apt install tesseract-ocr        # needed for scanned-page OCR (macOS: brew install tesseract)
    export AIM_SECRET="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
    uvicorn app:app --port 8000
Open http://localhost:8000. The site is served from static/index.html. A Sign in button appears in the top bar when the server is reachable.

## Deploy on Railway (recommended)
1. Push this folder to a GitHub repository.
2. Railway: New Project, Deploy from GitHub repo. It builds the Dockerfile and listens on $PORT automatically.
3. Variables: AIM_SECRET (a long random string), AIM_DB=/data/aim.db
4. Add a Volume mounted at /data so accounts, projects and the audit log survive redeploys.
5. Settings, Networking: Generate Domain. Open the URL and register the first account.
Plan: Hobby (about $5 a month plus usage).

## Deploy with Docker
Docker: docker build -t aimsquare . && docker run -p 8000:8000 -e AIM_SECRET=... -v aim_data:/data aimsquare
Any host that runs Docker works (Render, Railway, Fly.io). Put it behind HTTPS. To host the page elsewhere, open it with ?api=https://your-server and set AIM_CORS to that page's origin.

## Settings (environment variables)
AIM_SECRET (required in production), ANTHROPIC_API_KEY (switches the assistant on), AIM_MODEL (default claude-sonnet-5-5), AIM_AI_RATE_PER_MIN (default 12 questions a minute per user), AIM_DB (database path), AIM_CORS (allowed origins, default *), AIM_MAX_PDF_MB (30), AIM_TOKEN_HOURS (12)

## Endpoints
POST /api/auth/register, /api/auth/login
POST /api/pdf/extract
GET/POST /api/projects; GET/PUT/DELETE /api/projects/{id}
GET /api/projects/{id}/export?format=docx|pdf
POST /api/assistant
GET /api/audit; GET /api/audit/verify

## Assistant
A side panel (top bar, Assistant) that answers questions about the loaded analysis. The page sends the loaded balance-sheet and P&L lines, the Section 138 test and the SA 610 answers with each question; the server adds fixed rules and calls the Anthropic API with your key, which never reaches the browser. It answers only from that data, cites the line or law it used (tags open the matching row), says plainly when something is not loaded, and explains and suggests without concluding fraud. Vendors, governance, litigation, cash flow, tax and segment tabs are not sent. Switch it on by setting ANTHROPIC_API_KEY on the server; without it the panel says it is off. Each question costs a small per-use API charge. The audit log records a fingerprint of each exchange, not its text.

## Support agent
A second side panel (top bar, Support) is a Claude Managed Agent that answers customers from your Notion docs and hands off to a person through Slack when it is not confident. Its definition is in `../support-agent/agents/support-agent.md`. The server creates one agent session per conversation, sends the customer's name and email with each question, and returns the agent's reply. Each customer can only use their own conversations.

Set on the server: AIM_SUPPORT_AGENT_ID (the agent_... ID), AIM_SUPPORT_ENV_ID (from tools/create_support_environment.py), AIM_SUPPORT_VAULT_IDS (comma-separated vault IDs holding the Notion and Slack credentials). Without the first two the Support button does not appear. Calls use the Managed Agents beta, so check the current docs if they change.

## Data handling
PDFs are processed in memory and not stored; with the assistant on, the loaded figures and your question are sent to the AI provider for each question; only their SHA-256 fingerprint goes in the audit log. Saved projects hold analysis results, not source files. Passwords use PBKDF2-SHA256 (200k iterations).

## Audit log
Every event stores the previous event's hash, so editing any past row breaks the chain and /api/audit/verify reports where. Deleting the most recent events cannot be detected from the database alone: note the head hash after important sessions (or email it to yourself) to catch truncation. This is tamper-evident, not blockchain-grade; strong proof needs the head hash anchored outside your server.

## Limits
OCR can misread digits (for example 17,292 read as 17,282), so figures extracted from scanned PDFs must be checked against the source. The log is one chain for the whole server. Run `python test_backend.py file.pdf` to re-check everything.
