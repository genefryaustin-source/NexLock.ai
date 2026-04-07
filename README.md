
# NexlockAI Evidence Vault — Hardened (SOC 2 oriented)

Implements:
- **bcrypt** password hashing (cost 12) + password policy
- **Password reset** (SuperAdmin generates one-time token w/ expiry)
- **Row-level tenant isolation** (SuperAdmin selects tenant; others locked)
- **Audit logging** (append-only table + UI export)
- PKI verification UI badges (🟢/🔴)
- FedRAMP-style POA&M auto-generation from evidence gaps
- Quarterly evidence diffing
- Trust Center auto-publish from DB

## Run
```bash
pip install -r requirements.txt
streamlit run app.py
```

## Default SuperAdmin (seeded on first run)
- admin@nexlock.ai
- ChangeMeNow!1#
(Forced password change at first login)

## Trust Center
Host `trust_center/` as a static site.
- Public: `index.html?token=public`
- NDA/Enterprise: `index.html?token=<customer token>`
