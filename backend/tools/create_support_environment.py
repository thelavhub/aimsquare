"""One-time helper: creates the sandbox environment the support agent runs in and prints its ID.
Run from the backend folder:  .venv\\Scripts\\python tools\\create_support_environment.py
The key is typed at the prompt and is not saved anywhere."""
import getpass, sys
import httpx

key = getpass.getpass("Anthropic API key (nothing shows as you type): ").strip()
if not key:
    sys.exit("No key entered.")
r = httpx.post(
    "https://api.anthropic.com/v1/environments?beta=true",
    headers={"x-api-key": key, "anthropic-version": "2026-10-21", "anthropic-beta": "managed-agents-2026-04-01", "content-type": "application/json"},
    json={"name": "aimsquare-support", "config": {"type": "cloud", "networking": {"type": "limited", "allow_package_managers": False}}},
    timeout=60,
)
if r.status_code >= 300:
    sys.exit("Failed (%d): %s" % (r.status_code, r.text[:400]))
print("\nEnvironment ID:", r.json()["id"])
print("Set it as AIM_SUPPORT_ENV_ID on the server.")
