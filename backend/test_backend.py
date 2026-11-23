"""End-to-end check:  python test_backend.py [path/to/some.pdf ...]"""
import os, sys, tempfile, time, sqlite3
os.environ["AIM_DB"] = os.path.join(tempfile.mkdtemp(), "t.db"); os.environ["AIM_SECRET"] = "test-secret"
from fastapi.testclient import TestClient
import app as A
c = TestClient(A.app)
ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg) or (cond or sys.exit(1))

ok(c.get("/api/health").json()["ok"], "health")
ok(c.post("/api/pdf/extract", files={"file": ("x.pdf", b"%PDF-1.4")}).status_code == 401, "extract needs login")
r = c.post("/api/auth/register", json={"email": "van@example.com", "password": "correct-horse", "name": "Van"}); ok(r.status_code == 200, "register")
ok(c.post("/api/auth/register", json={"email": "van@example.com", "password": "correct-horse"}).status_code == 409, "duplicate email blocked")
ok(c.post("/api/auth/login", json={"email": "van@example.com", "password": "wrong-password"}).status_code == 401, "bad password blocked")
tok = c.post("/api/auth/login", json={"email": "van@example.com", "password": "correct-horse"}).json()["token"]; H = {"Authorization": "Bearer " + tok}
ok(c.get("/api/projects", headers={"Authorization": "Bearer " + tok[:-3] + "xxx"}).status_code == 401, "forged token rejected")
ok(c.post("/api/pdf/extract", headers=H, files={"file": ("x.txt", b"hello")}).status_code == 415, "non-PDF rejected")

for p in sys.argv[1:]:
    t = time.time(); r = c.post("/api/pdf/extract", headers=H, files={"file": (os.path.basename(p), open(p, "rb").read(), "application/pdf")}); j = r.json()
    ok(r.status_code == 200 and j["rows"], f"extract {os.path.basename(p)[:30]}: {j['pages']} pages, {j['ocr_pages']} via OCR, {j['row_count']} rows, {time.time()-t:.0f}s")
    print("   sample:", [x for x in j["rows"] if x[0].lower().startswith(("revenue from operations", "property, plant", "total assets", "purchases of stock"))][:3])

data = {"matchedB": [{"name": "Trade payables (others)", "cur": 4171, "yoy": 1.4, "band": "High", "score": 80, "chk": "Supplier-statement reconciliation"}],
        "matchedP": [{"name": "Revenue from operations", "cur": 20211, "yoy": None, "band": "Medium", "score": 40, "chk": "Cut-off & <b>markup</b> & test"}], "unmatched": ["x"]}
pid = c.post("/api/projects", headers=H, json={"name": "Eternal Q1 <test>", "data": data}).json()["id"]
ok(c.put(f"/api/projects/{pid}", headers=H, json={"name": "Eternal Q1", "data": data}).json()["saved"], "save project")
ok(c.get(f"/api/projects/{pid}", headers=H).json()["data"]["matchedB"][0]["cur"] == 4171, "load project")
c.post("/api/auth/register", json={"email": "other@example.com", "password": "another-pass1"}); t2 = c.post("/api/auth/login", json={"email": "other@example.com", "password": "another-pass1"}).json()["token"]
ok(c.get(f"/api/projects/{pid}", headers={"Authorization": "Bearer " + t2}).status_code == 404, "other users cannot open my project")
for fmt, magic in (("docx", b"PK"), ("pdf", b"%PDF")):
    r = c.get(f"/api/projects/{pid}/export?format={fmt}", headers=H); ok(r.status_code == 200 and r.content.startswith(magic), f"export {fmt} ({len(r.content)} bytes)")
# ---- assistant ----
CTX = {"balanceSheet": {"items": [{"key": "Inventories", "cur": 980}]}}
ok(c.post("/api/assistant", headers=H, json={"question": "hi", "context": CTX}).status_code == 503, "assistant says so when no API key is set")
ok(c.post("/api/assistant", json={"question": "hi", "context": CTX}).status_code == 401, "assistant needs login")
A.AI_KEY = "test-key"; seen = {}
async def fake(system, messages, model=None):
    seen["system"], seen["messages"] = system, messages
    return "Check [[B:Inventories]] first."
A.call_model = fake
ok(c.get("/api/health").json()["assistant"] is True, "health reports assistant on")
r = c.post("/api/assistant", headers=H, json={"question": "What first?", "context": CTX,
    "history": [{"role": "assistant", "content": "stray"}, {"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}, {"role": "user", "content": "unanswered"}]})
ok(r.status_code == 200 and "[[B:Inventories]]" in r.json()["answer"], "assistant answers")
ok("<analysis>" in seen["system"] and '"Inventories"' in seen["system"] and "never conclude" in seen["system"].lower().replace("never conclude or imply", "never conclude"), "analysis and rules reach the model")
ok([m["role"] for m in seen["messages"]] == ["user", "assistant", "user"] and seen["messages"][-1]["content"] == "What first?", "turns alternate and end with the new question")
ok(c.post("/api/assistant", headers=H, json={"question": "x" * 1001, "context": CTX}).status_code == 422, "overlong question rejected")
ok(c.post("/api/assistant", headers=H, json={"question": "big", "context": {"x": "y" * 210000}}).status_code == 413, "oversized context rejected")
A.AI_RATE_PER_MIN = 3
codes = [c.post("/api/assistant", headers=H, json={"question": "q", "context": CTX}).status_code for _ in range(3)]
ok(429 in codes, "rate limit applies")
rows = sqlite3.connect(os.environ["AIM_DB"]).execute("SELECT detail,payload_sha256 FROM audit WHERE action='assistant_query'").fetchall()
ok(rows and all(len(x[1]) == 64 and "Check" not in x[0] for x in rows), "assistant exchanges are logged by fingerprint, not text")
# ---- support agent ----
ok(c.post("/api/support", headers=H, json={"message": "hi"}).status_code == 503, "support says it is yet to be configured while switched off")
ok(c.get("/api/health").json()["support"] is False, "health reports support off by default")
A.SUP_ON = True
r = c.post("/api/support", headers=H, json={"message": "What does High priority mean?"})
ok(r.status_code == 200 and r.json()["session_id"] == "quick" and r.json()["reply"], "quick mode answers from the built-in guide when no agent is set")
A.SUP_AGENT, A.SUP_ENV = "agent_x", "env_x"
ok(c.get("/api/health").json()["support"] is True, "health reports support on")
made = []
async def fake_new(title):
    made.append(title); return "sesn_test%d" % len(made)
turns = []
async def fake_turn(sid, text):
    turns.append((sid, text)); return "See [the guide](https://example.com/guide)."
A.support_new_session, A.support_turn = fake_new, fake_turn
r = c.post("/api/support", headers=H, json={"message": "How do I export?"}).json()
ok(r["session_id"] == "sesn_test1" and "guide" in r["reply"], "support answers and opens a session")
ok("Customer:" in turns[-1][1] and "How do I export?" in turns[-1][1] and "@" in turns[-1][1], "agent is told who is asking")
r2 = c.post("/api/support", headers=H, json={"message": "and PDF?", "session_id": r["session_id"]}).json()
ok(r2["session_id"] == r["session_id"] and len(made) == 1, "follow-up reuses the session")
ok(c.post("/api/support", headers={"Authorization": "Bearer " + t2}, json={"message": "x", "session_id": r["session_id"]}).status_code == 404, "other users cannot use my support session")
ok(c.post("/api/support", json={"message": "x"}).status_code == 401, "support needs login")
A.SUP_RATE_PER_MIN = 3
ok(429 in [c.post("/api/support", headers=H, json={"message": "q", "session_id": r["session_id"]}).status_code for _ in range(3)], "support rate limit applies")
v = c.get("/api/audit/verify", headers=H).json(); ok(v["ok"], f"audit chain intact: {v['events']} events, head {v['head'][:12]}…")
db = sqlite3.connect(os.environ["AIM_DB"]); db.execute("UPDATE audit SET action='project_delete' WHERE seq=3"); db.commit()
v = c.get("/api/audit/verify", headers=H).json(); ok(not v["ok"] and v["broken_at_seq"] == 3, f"tampering detected at event #{v['broken_at_seq']}")
print("ALL CHECKS PASSED")
