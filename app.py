
import base64
import hashlib
import json
import sqlite3
import zipfile
from io import BytesIO
from datetime import datetime, timedelta, date
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
import bcrypt

import pandas as pd
import streamlit as st

# Prefer cryptography for PKI verification
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.exceptions import InvalidSignature
    CRYPTO_OK = True
except Exception:
    CRYPTO_OK = False

ROOT = Path(__file__).parent
DATA = ROOT / "data"
UPLOADS = ROOT / "uploads"
EXPORTS = ROOT / "exports"
TRUST_CENTER = ROOT / "trust_center"
for d in (DATA, UPLOADS, EXPORTS, TRUST_CENTER):
    d.mkdir(exist_ok=True)

DB_PATH = DATA / "evidence_vault.db"

CONTROLS = [
    ("CC1","Control Environment"),("CC2","Communication"),("CC3","Risk Assessment"),
    ("CC4","Monitoring"),("CC5","Control Activities"),("CC6","Access Controls"),
    ("CC7","System Operations"),("CC8","Change Management"),("CC9","Risk Mitigation"),
    ("A","Availability"),("PI","Processing Integrity"),("C","Confidentiality"),("P","Privacy")
]

DETAILS = {
    "CC1":"Leadership oversight and governance cadence maintained; policy approvals tracked.",
    "CC2":"Training/comms cadence maintained; external inquiry workflow defined.",
    "CC3":"Risk register maintained and reviewed; treatment decisions documented.",
    "CC4":"Continuous monitoring with alert review and periodic evaluation.",
    "CC5":"Controls designed/implemented based on gap analysis and tested.",
    "CC6":"Access approvals, MFA enforcement, and periodic reviews executed.",
    "CC7":"Ops procedures executed: patching, monitoring, incident readiness.",
    "CC8":"Change approvals, testing, and rollback readiness documented.",
    "CC9":"Mitigation tracking and exception governance maintained.",
    "A":"Backups and DR tests executed on defined cadence.",
    "PI":"Data validation and integrity monitoring in place.",
    "C":"Classification, encryption, and DLP controls enforced.",
    "P":"Privacy controls and regulatory practices implemented."
}

SEVERITY_DEFAULTS = {
    "CC6":"High","CC7":"High","CC8":"High","A":"High",
    "CC3":"Moderate","CC4":"Moderate","C":"Moderate","P":"Moderate",
}

FEDRAMP_DOCUMENT_FAMILIES = [
    ("AC", "Access Control"),
    ("AT", "Awareness and Training"),
    ("AU", "Audit and Accountability"),
    ("CA", "Assessment, Authorization, and Monitoring"),
    ("CM", "Configuration Management"),
    ("CP", "Contingency Planning"),
    ("IA", "Identification and Authentication"),
    ("IR", "Incident Response"),
    ("MA", "Maintenance"),
    ("MP", "Media Protection"),
    ("PE", "Physical and Environmental Protection"),
    ("PL", "Planning"),
    ("PM", "Program Management"),
    ("PS", "Personnel Security"),
    ("RA", "Risk Assessment"),
    ("SA", "System and Services Acquisition"),
    ("SC", "System and Communications Protection"),
    ("SI", "System and Information Integrity"),
    ("SR", "Supply Chain Risk Management"),
]

CONTROL_BASELINES = {
    "AC": ["AC-1", "AC-2", "AC-3", "AC-5", "AC-6", "AC-17", "AC-18", "AC-19", "AC-20", "AC-22"],
    "AT": ["AT-1", "AT-2", "AT-3"],
    "AU": ["AU-1", "AU-2", "AU-3", "AU-6", "AU-8", "AU-11", "AU-12"],
    "CA": ["CA-1", "CA-2", "CA-5", "CA-7", "CA-8", "CA-9"],
    "CM": ["CM-1", "CM-2", "CM-3", "CM-4", "CM-6", "CM-8", "CM-10"],
    "CP": ["CP-1", "CP-2", "CP-3", "CP-4", "CP-6", "CP-9", "CP-10"],
    "IA": ["IA-1", "IA-2", "IA-4", "IA-5", "IA-8"],
    "IR": ["IR-1", "IR-2", "IR-4", "IR-5", "IR-6", "IR-8"],
    "MA": ["MA-1", "MA-2", "MA-4", "MA-5"],
    "MP": ["MP-1", "MP-2", "MP-4", "MP-5", "MP-6", "MP-7"],
    "PE": ["PE-1", "PE-2", "PE-3", "PE-6", "PE-8", "PE-18"],
    "PL": ["PL-1", "PL-2", "PL-4", "PL-8", "PL-10"],
    "PM": ["PM-1", "PM-2", "PM-5", "PM-9", "PM-11", "PM-12", "PM-30"],
    "PS": ["PS-1", "PS-2", "PS-3", "PS-4", "PS-5", "PS-6"],
    "RA": ["RA-1", "RA-2", "RA-3", "RA-5", "RA-7"],
    "SA": ["SA-1", "SA-2", "SA-3", "SA-4", "SA-9", "SA-10", "SA-11", "SA-15", "SA-22"],
    "SC": ["SC-1", "SC-7", "SC-8", "SC-12", "SC-13", "SC-28", "SC-39"],
    "SI": ["SI-1", "SI-2", "SI-3", "SI-4", "SI-5", "SI-7", "SI-10", "SI-12"],
    "SR": ["SR-1", "SR-2", "SR-3", "SR-5", "SR-6", "SR-11"],
}

DOCUMENT_TYPES = ["Policy", "Procedure", "Standard", "Plan", "Playbook", "Guideline"]
DOCUMENT_STATUSES = ["Draft", "In Review", "Approved", "Archived"]
APPROVAL_STATUSES = ["Pending", "Approved", "Rejected"]
REVIEW_FREQUENCIES = ["Quarterly", "Semi-Annual", "Annual"]
SENIOR_APPROVER_TITLES = ["CISO", "CIO", "Chief Compliance Officer", "Authorizing Official", "Senior Management Representative"]

def utcnow_iso():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def connect():
    return sqlite3.connect(DB_PATH)

def q(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return cur

def init_db():
    with connect() as conn:
        # tenants
        q(conn, """
        CREATE TABLE IF NOT EXISTS tenants(
            tenant_id TEXT PRIMARY KEY,
            tenant_name TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)
        # users (MVP auth)
        q(conn, """
        CREATE TABLE IF NOT EXISTS users(
            user_id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            display_name TEXT,
            role TEXT NOT NULL CHECK(role IN ('SuperAdmin','TenantAdmin','Auditor')),
            tenant_id TEXT,
            password_hash TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY(tenant_id) REFERENCES tenants(tenant_id)
        )
        """)
        # evidence
        q(conn, """
        CREATE TABLE IF NOT EXISTS evidence(
            evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            artifact_name TEXT NOT NULL,
            artifact_type TEXT NOT NULL,
            owner TEXT NOT NULL,
            period_start TEXT NOT NULL,
            period_end TEXT NOT NULL,
            source_system TEXT,
            file_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            notes TEXT,
            uploaded_by TEXT,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(tenant_id) REFERENCES tenants(tenant_id)
        )
        """)
        # signatures (for UI verify badges)
        q(conn, """
        CREATE TABLE IF NOT EXISTS evidence_signatures(
            signature_id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL,
            signer TEXT NOT NULL,
            alg TEXT NOT NULL,
            public_key_pem TEXT,
            signature_b64 TEXT NOT NULL,
            signed_at TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            verified_at TEXT,
            verify_message TEXT,
            FOREIGN KEY(evidence_id) REFERENCES evidence(evidence_id)
        )
        """)
        # timestamps
        q(conn, """
        CREATE TABLE IF NOT EXISTS evidence_timestamps(
            timestamp_id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL,
            tsa_type TEXT NOT NULL,
            token_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            verified_at TEXT,
            verify_message TEXT,
            FOREIGN KEY(evidence_id) REFERENCES evidence(evidence_id)
        )
        """)
        # exceptions
        q(conn, """
        CREATE TABLE IF NOT EXISTS exceptions(
            exception_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            description TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            compensating_controls TEXT,
            owner TEXT NOT NULL,
            approval TEXT,
            expires_on TEXT,
            status TEXT NOT NULL CHECK(status IN ('Open','Approved','Expired','Closed')),
            created_at TEXT NOT NULL,
            FOREIGN KEY(tenant_id) REFERENCES tenants(tenant_id)
        )
        """)
        # POA&M
        q(conn, """
        CREATE TABLE IF NOT EXISTS poam_items(
            poam_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            weakness_description TEXT NOT NULL,
            severity TEXT NOT NULL,
            scheduled_completion_date TEXT,
            milestones_json TEXT,
            resources_required TEXT,
            compensating_controls TEXT,
            status TEXT NOT NULL CHECK(status IN ('Open','In Progress','Complete')),
            source TEXT,
            owner TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(tenant_id) REFERENCES tenants(tenant_id)
        )
        """)
        # Trust Center customers
        q(conn, """
        CREATE TABLE IF NOT EXISTS trust_customers(
            customer_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            customer_name TEXT NOT NULL,
            tier TEXT NOT NULL CHECK(tier IN ('PUBLIC','NDA','ENTERPRISE')),
            token TEXT NOT NULL,
            token_expires_utc TEXT,
            nda_accepted_utc TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(tenant_id) REFERENCES tenants(tenant_id)
        )
        """)

        # FedRAMP document governance
        q(conn, """
        CREATE TABLE IF NOT EXISTS documents(
            document_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            family_id TEXT NOT NULL,
            doc_type TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            owner TEXT NOT NULL,
            approver_name TEXT,
            approver_title TEXT,
            senior_management_approval_required INTEGER NOT NULL DEFAULT 1,
            review_frequency TEXT NOT NULL DEFAULT 'Annual',
            current_version_id TEXT,
            status TEXT NOT NULL CHECK(status IN ('Draft','In Review','Approved','Archived')) DEFAULT 'Draft',
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_reviewed_at TEXT,
            next_review_due TEXT,
            FOREIGN KEY(tenant_id) REFERENCES tenants(tenant_id)
        )
        """)
        q(conn, """
        CREATE TABLE IF NOT EXISTS document_versions(
            version_id TEXT PRIMARY KEY,
            document_id TEXT NOT NULL,
            version_label TEXT NOT NULL,
            content_md TEXT NOT NULL,
            change_summary TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            is_major INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY(document_id) REFERENCES documents(document_id)
        )
        """)
        q(conn, """
        CREATE TABLE IF NOT EXISTS document_approvals(
            approval_id TEXT PRIMARY KEY,
            document_id TEXT NOT NULL,
            version_id TEXT NOT NULL,
            requested_by TEXT,
            requested_at TEXT NOT NULL,
            approver_name TEXT NOT NULL,
            approver_title TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('Pending','Approved','Rejected')) DEFAULT 'Pending',
            decided_at TEXT,
            decision_notes TEXT,
            FOREIGN KEY(document_id) REFERENCES documents(document_id),
            FOREIGN KEY(version_id) REFERENCES document_versions(version_id)
        )
        """)
        q(conn, """
        CREATE TABLE IF NOT EXISTS document_reviews(
            review_id TEXT PRIMARY KEY,
            document_id TEXT NOT NULL,
            version_id TEXT,
            reviewer_name TEXT NOT NULL,
            reviewer_role TEXT,
            review_notes TEXT,
            reviewed_at TEXT NOT NULL,
            outcome TEXT,
            FOREIGN KEY(document_id) REFERENCES documents(document_id)
        )
        """)


        # seed default tenant + superadmin
        if q(conn, "SELECT COUNT(*) FROM tenants").fetchone()[0] == 0:
            q(conn, "INSERT INTO tenants(tenant_id, tenant_name, created_at) VALUES (?,?,?)",
              ("tenant_nexlockai","NexlockAI", utcnow_iso()))
        if q(conn, "SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            # Default password: ChangeMeNow! (change immediately)
            email = "admin@nexlock.ai"
            pwd = "ChangeMeNow!"
            ph = hashlib.sha256((email.lower()+pwd).encode("utf-8")).hexdigest()
            q(conn, """
                INSERT INTO users(user_id,email,display_name,role,tenant_id,password_hash,is_active,created_at)
                VALUES (?,?,?,?,?,?,?,?)
            """, ("user_superadmin", email, "Super Admin", "SuperAdmin", None, ph, 1, utcnow_iso()))
        conn.commit()






def verify_login(email: str, password: str) -> Optional[Dict[str, Any]]:
    email_l = email.strip().lower()

    with connect() as conn:
        row = q(conn, """
            SELECT user_id,email,display_name,role,tenant_id,is_active,password_hash
            FROM users WHERE email=?
        """, (email_l,)).fetchone()

    # ❌ USER NOT FOUND → log failure
    if not row:
        with connect() as conn:
            conn.execute("""
                INSERT INTO login_events (user_id, timestamp, success)
                VALUES (?, ?, ?)
            """, (None, datetime.utcnow().isoformat(), 0))
        return None

    user_id = row[0]
    stored_hash = row[6]

    # ❌ INACTIVE USER → log failure
    if int(row[5]) != 1:
        with connect() as conn:
            conn.execute("""
                INSERT INTO login_events (user_id, timestamp, success)
                VALUES (?, ?, ?)
            """, (user_id, datetime.utcnow().isoformat(), 0))
        return None

    # 🔐 bcrypt path
    if stored_hash.startswith("$2b$"):
        if bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
            with connect() as conn:
                conn.execute("""
                    INSERT INTO login_events (user_id, timestamp, success)
                    VALUES (?, ?, ?)
                """, (user_id, datetime.utcnow().isoformat(), 1))

            return {
                "user_id": row[0],
                "email": row[1],
                "display_name": row[2] or row[1],
                "role": row[3],
                "tenant_id": row[4]
            }

    # 🔁 legacy SHA256
    legacy_hash = hashlib.sha256((email_l + password).encode("utf-8")).hexdigest()

    if legacy_hash == stored_hash:
        # 🔄 upgrade to bcrypt
        new_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        with connect() as conn:
            conn.execute("""
                UPDATE users SET password_hash=?
                WHERE email=?
            """, (new_hash, email_l))

            # ✅ log success
            conn.execute("""
                INSERT INTO login_events (user_id, timestamp, success)
                VALUES (?, ?, ?)
            """, (user_id, datetime.utcnow().isoformat(), 1))

        return {
            "user_id": row[0],
            "email": row[1],
            "display_name": row[2] or row[1],
            "role": row[3],
            "tenant_id": row[4]
        }

    # ❌ WRONG PASSWORD → log failure
    with connect() as conn:
        conn.execute("""
            INSERT INTO login_events (user_id, timestamp, success)
            VALUES (?, ?, ?)
        """, (user_id, datetime.utcnow().isoformat(), 0))

    return None
def require_role(allowed: List[str]):
    if "auth" not in st.session_state or not st.session_state.auth:
        st.stop()
    if st.session_state.auth["role"] not in allowed:
        st.error("Access denied for this role.")
        st.stop()

def control_name(cid: str) -> str:
    for c,n in CONTROLS:
        if c==cid: return n
    return cid

def tenant_name(tenant_id: str) -> str:
    with connect() as conn:
        r = q(conn, "SELECT tenant_name FROM tenants WHERE tenant_id=?", (tenant_id,)).fetchone()
    return r[0] if r else tenant_id

def list_tenants() -> pd.DataFrame:
    with connect() as conn:
        return pd.read_sql_query("SELECT tenant_id, tenant_name, created_at FROM tenants ORDER BY tenant_name", conn)

def list_evidence(tenant_id: str, control_id: Optional[str]=None) -> pd.DataFrame:
    with connect() as conn:
        if control_id:
            return pd.read_sql_query("SELECT * FROM evidence WHERE tenant_id=? AND control_id=? ORDER BY uploaded_at DESC", conn, params=(tenant_id,control_id))
        return pd.read_sql_query("SELECT * FROM evidence WHERE tenant_id=? ORDER BY uploaded_at DESC", conn, params=(tenant_id,))

def evidence_last_by_control(tenant_id: str) -> Dict[str, Optional[datetime]]:
    out = {}
    with connect() as conn:
        for cid,_ in CONTROLS:
            row = q(conn, "SELECT uploaded_at FROM evidence WHERE tenant_id=? AND control_id=? ORDER BY uploaded_at DESC LIMIT 1", (tenant_id,cid)).fetchone()
            out[cid] = datetime.fromisoformat(row[0].replace("Z","")) if row else None
    return out

def derive_control_status(tenant_id: str, lookback_days: int=90) -> List[Dict[str, Any]]:
    cutoff = datetime.utcnow() - timedelta(days=lookback_days)
    last = evidence_last_by_control(tenant_id)
    rows = []
    for cid,cname in CONTROLS:
        dt = last[cid]
        status = "On Track" if (dt and dt >= cutoff) else "Needs Attention"
        rows.append({"id":cid,"name":cname,"status":status,"last_tested":dt.strftime("%Y-%m-%d") if dt else None,"details":DETAILS.get(cid,"—")})
    return rows

def verify_signature_rsapss_sha256(public_key_pem: str, artifact_sha256_hex: str, signature_b64: str) -> Tuple[bool,str]:
    try:
        sig = base64.b64decode(signature_b64.strip())
    except Exception:
        return False, "Signature base64 decode failed."
    try:
        digest = bytes.fromhex(artifact_sha256_hex.strip().lower())
    except Exception:
        return False, "Artifact SHA-256 invalid."
    if len(digest) != 32:
        return False, "Artifact SHA-256 must be 32 bytes."
    if not CRYPTO_OK:
        return False, "Install `cryptography` for in-app PKI verification."
    try:
        pub = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        pub.verify(sig, digest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True, "Verified."
    except InvalidSignature:
        return False, "Invalid signature."
    except Exception as e:
        return False, f"Verification error: {e}"

def poam_severity(cid: str) -> str:
    return SEVERITY_DEFAULTS.get(cid, "Low")

def generate_poam_items(tenant_id: str, lookback_days: int=90) -> List[Dict[str, Any]]:
    cutoff = datetime.utcnow() - timedelta(days=lookback_days)
    last = evidence_last_by_control(tenant_id)

    exceptions_by_control: Dict[str, List[str]] = {}
    with connect() as conn:
        for cid, comp in q(conn, "SELECT control_id, compensating_controls FROM exceptions WHERE tenant_id=? AND status IN ('Open','Approved')", (tenant_id,)).fetchall():
            exceptions_by_control.setdefault(cid, []).append(comp or "")

    items = []
    idx = 1
    created_at = utcnow_iso()
    for cid,cname in CONTROLS:
        weaknesses = []
        source = None
        if last[cid] is None:
            weaknesses.append(f"Missing evidence for {cid} ({cname}) within the audit window.")
            source = "Evidence Vault (missing)"
        elif last[cid] < cutoff:
            weaknesses.append(f"Stale evidence for {cid} ({cname}). Last evidence: {last[cid].date().isoformat()}")
            source = "Evidence Vault (stale)"

        for w in weaknesses:
            sev = poam_severity(cid)
            days = 30 if sev=="High" else 60 if sev=="Moderate" else 90
            due = (datetime.utcnow() + timedelta(days=days)).date().isoformat()
            milestones = [
                {"m":"Identify root cause","due":(datetime.utcnow()+timedelta(days=7)).date().isoformat()},
                {"m":"Implement fix / collect evidence","due":(datetime.utcnow()+timedelta(days=max(14,days-7))).date().isoformat()},
                {"m":"Validate + owner attestation","due":due},
            ]
            comp = "; ".join([c for c in exceptions_by_control.get(cid,[]) if c])
            poam_id = f"POAM-{idx:03d}"
            items.append({
                "poam_id":poam_id,"control_id":cid,"weakness_description":w,"severity":sev,
                "scheduled_completion_date":due,"milestones_json":json.dumps(milestones),
                "resources_required":"Compliance + Control Owner time",
                "compensating_controls":comp,"status":"Open","source":source or "",
                "owner":"Compliance","created_at":created_at
            })
            idx += 1
    return items

def upsert_poam(tenant_id: str, items: List[Dict[str, Any]]):
    with connect() as conn:
        for it in items:
            q(conn, """
                INSERT OR REPLACE INTO poam_items(
                    poam_id, tenant_id, control_id, weakness_description, severity, scheduled_completion_date,
                    milestones_json, resources_required, compensating_controls, status, source, owner, created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                it["poam_id"], tenant_id, it["control_id"], it["weakness_description"], it["severity"],
                it["scheduled_completion_date"], it["milestones_json"], it["resources_required"],
                it["compensating_controls"], it["status"], it["source"], it["owner"], it["created_at"]
            ))
        conn.commit()

def poam_to_xlsx_bytes(items: List[Dict[str, Any]]) -> bytes:
    import openpyxl
    from io import BytesIO
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "POA&M"
    ws.append([
        "POA&M Item ID","Control ID","Weakness Description","Severity",
        "Scheduled Completion Date","Milestones (JSON)","Resources Required",
        "Compensating Controls","Status","Source","Owner","Created At"
    ])
    for it in items:
        ws.append([it["poam_id"],it["control_id"],it["weakness_description"],it["severity"],it["scheduled_completion_date"],
                   it["milestones_json"],it["resources_required"],it["compensating_controls"],it["status"],it["source"],it["owner"],it["created_at"]])
    bio = BytesIO()
    wb.save(bio)
    return bio.getvalue()

def quarter_bounds(year: int, quarter: int):
    if quarter==1: return date(year,1,1), date(year,3,31)
    if quarter==2: return date(year,4,1), date(year,6,30)
    if quarter==3: return date(year,7,1), date(year,9,30)
    if quarter==4: return date(year,10,1), date(year,12,31)
    raise ValueError("quarter must be 1-4")

def summarize_quarter(tenant_id: str, year: int, quarter: int) -> pd.DataFrame:
    ps, pe = quarter_bounds(year, quarter)
    with connect() as conn:
        df = pd.read_sql_query("""
            SELECT control_id, COUNT(*) AS artifacts, MAX(uploaded_at) AS last_uploaded, MIN(uploaded_at) AS first_uploaded
            FROM evidence
            WHERE tenant_id=? AND date(uploaded_at) BETWEEN date(?) AND date(?)
            GROUP BY control_id
        """, conn, params=(tenant_id, ps.isoformat(), pe.isoformat()))
    allc = pd.DataFrame({"control_id":[c for c,_ in CONTROLS]})
    out = allc.merge(df, on="control_id", how="left").fillna({"artifacts":0})
    out["control_name"] = out["control_id"].apply(control_name)
    return out[["control_id","control_name","artifacts","first_uploaded","last_uploaded"]]

def diff_quarters(a: pd.DataFrame, b: pd.DataFrame) -> pd.DataFrame:
    m = a.merge(b, on="control_id", suffixes=("_a","_b"))
    m["control_name"] = m["control_id"].apply(control_name)
    m["delta_artifacts"] = m["artifacts_b"] - m["artifacts_a"]
    def s(r):
        if r["artifacts_a"]==0 and r["artifacts_b"]>0: return "Improved (new evidence)"
        if r["artifacts_a"]>0 and r["artifacts_b"]==0: return "Regressed (no evidence)"
        if r["delta_artifacts"]>0: return "Improved"
        if r["delta_artifacts"]<0: return "Lower volume"
        return "No change"
    m["status"] = m.apply(s, axis=1)
    return m[["control_id","control_name","artifacts_a","artifacts_b","delta_artifacts","status","last_uploaded_a","last_uploaded_b"]]

def publish_trust_center(tenant_id: str, lookback_days: int=90) -> Path:
    payload = {
        "company": tenant_name(tenant_id),
        "last_updated_utc": utcnow_iso(),
        "trust_overview": {
            "security_program": "NexlockAI operates a SOC 2–aligned security and compliance program with continuous evidence collection.",
            "encryption": "Encryption at rest and in transit is enforced for in-scope systems.",
            "availability": "Backups and disaster recovery processes are tested on a defined cadence."
        },
        "controls": derive_control_status(tenant_id, lookback_days),
        "metrics": {
            "lookback_days": lookback_days,
            "controls_on_track": sum(1 for c in derive_control_status(tenant_id, lookback_days) if c["status"]=="On Track"),
            "controls_total": len(CONTROLS)
        },
        "contact": {"security_email":"security@nexlock.ai","privacy_email":"privacy@nexlock.ai"}
    }
    out = TRUST_CENTER / "trust_center_status.json"
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out

def export_customers_json(tenant_id: str) -> Path:
    with connect() as conn:
        rows = pd.read_sql_query("""
            SELECT customer_id, customer_name, tier, token, token_expires_utc
            FROM trust_customers WHERE tenant_id=?
        """, conn, params=(tenant_id,))
    out = TRUST_CENTER / "customers.json"
    out.write_text(json.dumps({"customers": rows.to_dict(orient="records")}, indent=2), encoding="utf-8")
    return out

def document_family_name(fid: str) -> str:
    for code, name in FEDRAMP_DOCUMENT_FAMILIES:
        if code == fid:
            return name
    return fid


def review_due_date(review_frequency: str) -> str:
    base = datetime.utcnow().date()
    delta_days = {"Quarterly": 90, "Semi-Annual": 180, "Annual": 365}.get(review_frequency, 365)
    return (base + timedelta(days=delta_days)).isoformat()


def generate_document_template(family_id: str, doc_type: str, company_name: str, owner: str, approver_title: str) -> str:
    family_name = document_family_name(family_id)
    controls = ", ".join(CONTROL_BASELINES.get(family_id, [f"{family_id}-1"]))
    today = datetime.utcnow().date().isoformat()
    title = f"{company_name} {family_name} {doc_type}"
    return f'''# {title}

## 1. Document Control
- **Family:** {family_id} – {family_name}
- **Document Type:** {doc_type}
- **Document Owner:** {owner}
- **Approval Authority:** {approver_title}
- **Effective Date:** {today}
- **Review Frequency:** Annual
- **FedRAMP Baseline Mapping:** {controls}

## 2. Purpose
This document defines the governance requirements, mandatory expectations, and operational procedures used by {company_name} to satisfy FedRAMP control family {family_id}.

## 3. Scope
This document applies to all personnel, contractors, systems, services, data stores, management processes, and supporting technologies that are in scope for the {company_name} FedRAMP boundary.

## 4. Roles and Responsibilities
- **Senior Management Representative:** Reviews and approves this document and significant revisions.
- **Document Owner:** Maintains the document, coordinates reviews, and ensures procedures are operationalized.
- **System Owners:** Implement the required controls and maintain evidence.
- **Security / Compliance Team:** Monitors execution, performs reviews, and tracks findings and exceptions.
- **Workforce Members:** Follow this policy and associated procedures.

## 5. Policy Statements
1. {company_name} shall establish, document, approve, communicate, and maintain {family_name.lower()} requirements aligned to FedRAMP and NIST SP 800-53.
2. Control activities shall be implemented consistently, measured, and supported by retained evidence.
3. Deviations, exceptions, and control gaps shall be documented, risk-assessed, approved where required, and tracked to closure.
4. Reviews shall occur at least annually and upon material system, regulatory, or organizational change.

## 6. Procedures
### 6.1 Initiation
- Identify the systems, data flows, and stakeholders affected by this control family.
- Confirm applicable FedRAMP controls and inherited/shared responsibility boundaries.

### 6.2 Implementation
- Execute the documented control activities for {family_name.lower()}.
- Retain evidence in the NexlockAI evidence vault with ownership, period covered, and source metadata.
- Track changes through formal version control.

### 6.3 Review and Monitoring
- Review operating effectiveness on the defined cadence.
- Record observations, deficiencies, exceptions, and POA&M actions.
- Escalate material weaknesses to senior management.

### 6.4 Approval and Publication
- Submit draft updates for management approval before the document is considered effective.
- Do not overwrite approved content; issue a new version with a documented change summary.

## 7. Evidence Requirements
- Approved policy and procedure versions
- Evidence of implementation and recurring operation
- Review records and approvals
- Exceptions and POA&M records where applicable

## 8. Review Cycle
This document shall be reviewed no less than annually and when there are significant environmental, technical, regulatory, or organizational changes.

## 9. Version History
| Version | Date | Author | Summary |
|---|---|---|---|
| v1.0 | {today} | {owner} | Initial controlled template generated in NexlockAI |

## 10. Approval
- **Approved By:** ______________________________
- **Title:** {approver_title}
- **Approval Date:** ______________________________
- **Signature / Approval Record:** Recorded in NexlockAI document approvals
'''


def list_documents(tenant_id: str) -> pd.DataFrame:
    with connect() as conn:
        return pd.read_sql_query(
            """
            SELECT d.document_id, d.tenant_id, d.family_id, d.doc_type, d.title, d.description, d.owner,
                   d.approver_name, d.approver_title, d.review_frequency, d.status, d.current_version_id,
                   d.created_by, d.created_at, d.updated_at, d.last_reviewed_at, d.next_review_due
            FROM documents d
            WHERE d.tenant_id=?
            ORDER BY d.updated_at DESC, d.created_at DESC
            """,
            conn,
            params=(tenant_id,),
        )


def list_document_versions(document_id: str) -> pd.DataFrame:
    with connect() as conn:
        return pd.read_sql_query(
            """
            SELECT version_id, document_id, version_label, change_summary, created_by, created_at, is_major
            FROM document_versions
            WHERE document_id=?
            ORDER BY created_at DESC
            """,
            conn,
            params=(document_id,),
        )


def list_document_approvals(document_id: str) -> pd.DataFrame:
    with connect() as conn:
        return pd.read_sql_query(
            """
            SELECT approval_id, document_id, version_id, requested_by, requested_at, approver_name,
                   approver_title, status, decided_at, decision_notes
            FROM document_approvals
            WHERE document_id=?
            ORDER BY requested_at DESC
            """,
            conn,
            params=(document_id,),
        )


def list_document_reviews(document_id: str) -> pd.DataFrame:
    with connect() as conn:
        return pd.read_sql_query(
            """
            SELECT review_id, document_id, version_id, reviewer_name, reviewer_role, review_notes, reviewed_at, outcome
            FROM document_reviews
            WHERE document_id=?
            ORDER BY reviewed_at DESC
            """,
            conn,
            params=(document_id,),
        )


def get_document_with_content(document_id: str) -> Optional[Dict[str, Any]]:
    with connect() as conn:
        row = q(
            conn,
            """
            SELECT d.document_id, d.tenant_id, d.family_id, d.doc_type, d.title, d.description, d.owner,
                   d.approver_name, d.approver_title, d.review_frequency, d.status, d.current_version_id,
                   d.created_by, d.created_at, d.updated_at, d.last_reviewed_at, d.next_review_due,
                   v.version_id, v.version_label, v.content_md, v.change_summary, v.created_by AS version_created_by, v.created_at AS version_created_at
            FROM documents d
            LEFT JOIN document_versions v ON d.current_version_id = v.version_id
            WHERE d.document_id=?
            """,
            (document_id,),
        ).fetchone()
    if not row:
        return None
    columns = [
        "document_id", "tenant_id", "family_id", "doc_type", "title", "description", "owner", "approver_name", "approver_title",
        "review_frequency", "status", "current_version_id", "created_by", "created_at", "updated_at", "last_reviewed_at", "next_review_due",
        "version_id", "version_label", "content_md", "change_summary", "version_created_by", "version_created_at",
    ]
    return dict(zip(columns, row))


def next_version_label(current_label: Optional[str], major: bool = True) -> str:
    if not current_label:
        return "v1.0"
    raw = current_label.lower().lstrip("v")
    try:
        major_num, minor_num = raw.split(".")
        major_num = int(major_num)
        minor_num = int(minor_num)
    except Exception:
        return "v1.0"
    if major:
        return f"v{major_num + 1}.0"
    return f"v{major_num}.{minor_num + 1}"


def create_document_record(tenant_id: str, family_id: str, doc_type: str, title: str, description: str, owner: str,
                           approver_name: str, approver_title: str, review_frequency: str, created_by: str, content_md: str) -> str:
    now = utcnow_iso()
    document_id = "doc_" + hashlib.md5(f"{tenant_id}|{title}|{now}".encode("utf-8")).hexdigest()[:12]
    version_id = "ver_" + hashlib.md5(f"{document_id}|{now}".encode("utf-8")).hexdigest()[:12]
    with connect() as conn:
        q(
            conn,
            """
            INSERT INTO documents(document_id, tenant_id, family_id, doc_type, title, description, owner, approver_name, approver_title,
                                  senior_management_approval_required, review_frequency, current_version_id, status, created_by, created_at, updated_at, next_review_due)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (document_id, tenant_id, family_id, doc_type, title, description, owner, approver_name, approver_title, 1,
             review_frequency, version_id, "Draft", created_by, now, now, review_due_date(review_frequency)),
        )
        q(
            conn,
            """
            INSERT INTO document_versions(version_id, document_id, version_label, content_md, change_summary, created_by, created_at, is_major)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (version_id, document_id, "v1.0", content_md, "Initial controlled version", created_by, now, 1),
        )
        conn.commit()
    return document_id


def save_document_version(document_id: str, content_md: str, change_summary: str, created_by: str, major: bool = True) -> str:
    current = get_document_with_content(document_id)
    if not current:
        raise ValueError("Document not found")
    now = utcnow_iso()
    version_id = "ver_" + hashlib.md5(f"{document_id}|{now}".encode("utf-8")).hexdigest()[:12]
    version_label = next_version_label(current.get("version_label"), major=major)
    new_status = "Draft" if current.get("status") == "Approved" else (current.get("status") or "Draft")
    with connect() as conn:
        q(
            conn,
            """
            INSERT INTO document_versions(version_id, document_id, version_label, content_md, change_summary, created_by, created_at, is_major)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (version_id, document_id, version_label, content_md, change_summary, created_by, now, 1 if major else 0),
        )
        q(conn, "UPDATE documents SET current_version_id=?, updated_at=?, status=? WHERE document_id=?", (version_id, now, new_status, document_id))
        conn.commit()
    return version_id


def submit_document_for_approval(document_id: str, requested_by: str, approver_name: str, approver_title: str) -> str:
    current = get_document_with_content(document_id)
    if not current or not current.get("current_version_id"):
        raise ValueError("Document/version not found")
    now = utcnow_iso()
    approval_id = "apr_" + hashlib.md5(f"{document_id}|{now}".encode("utf-8")).hexdigest()[:12]
    with connect() as conn:
        q(
            conn,
            """
            INSERT INTO document_approvals(approval_id, document_id, version_id, requested_by, requested_at, approver_name, approver_title, status)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (approval_id, document_id, current["current_version_id"], requested_by, now, approver_name, approver_title, "Pending"),
        )
        q(conn, "UPDATE documents SET status=?, approver_name=?, approver_title=?, updated_at=? WHERE document_id=?", ("In Review", approver_name, approver_title, now, document_id))
        conn.commit()
    return approval_id


def decide_document_approval(approval_id: str, approver_name: str, approver_title: str, approve: bool, decision_notes: str) -> None:
    now = utcnow_iso()
    status = "Approved" if approve else "Rejected"
    with connect() as conn:
        row = q(conn, "SELECT document_id, version_id FROM document_approvals WHERE approval_id=?", (approval_id,)).fetchone()
        if not row:
            raise ValueError("Approval not found")
        document_id, version_id = row
        review_frequency = q(conn, "SELECT review_frequency FROM documents WHERE document_id=?", (document_id,)).fetchone()[0]
        q(
            conn,
            "UPDATE document_approvals SET approver_name=?, approver_title=?, status=?, decided_at=?, decision_notes=? WHERE approval_id=?",
            (approver_name, approver_title, status, now, decision_notes, approval_id),
        )
        doc_status = "Approved" if approve else "Draft"
        last_reviewed_at = now if approve else None
        next_due = review_due_date(review_frequency) if approve else None
        q(
            conn,
            "UPDATE documents SET status=?, approver_name=?, approver_title=?, updated_at=?, last_reviewed_at=?, next_review_due=? WHERE document_id=?",
            (doc_status, approver_name, approver_title, now, last_reviewed_at, next_due, document_id),
        )
        q(
            conn,
            """
            INSERT INTO document_reviews(review_id, document_id, version_id, reviewer_name, reviewer_role, review_notes, reviewed_at, outcome)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            ("rev_" + hashlib.md5(f"{approval_id}|{now}".encode("utf-8")).hexdigest()[:12], document_id, version_id, approver_name, approver_title, decision_notes, now, status),
        )
        conn.commit()


def add_document_review(document_id: str, version_id: Optional[str], reviewer_name: str, reviewer_role: str, review_notes: str, outcome: str) -> None:
    now = utcnow_iso()
    with connect() as conn:
        q(
            conn,
            """
            INSERT INTO document_reviews(review_id, document_id, version_id, reviewer_name, reviewer_role, review_notes, reviewed_at, outcome)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            ("rev_" + hashlib.md5(f"{document_id}|{reviewer_name}|{now}".encode("utf-8")).hexdigest()[:12], document_id, version_id, reviewer_name, reviewer_role, review_notes, now, outcome),
        )
        q(conn, "UPDATE documents SET last_reviewed_at=?, updated_at=? WHERE document_id=?", (now, now, document_id))
        conn.commit()


def document_dashboard_metrics(tenant_id: str) -> Dict[str, int]:
    df = list_documents(tenant_id)
    if df.empty:
        return {"total": 0, "approved": 0, "draft": 0, "in_review": 0, "overdue": 0}
    overdue = 0
    today = datetime.utcnow().date()
    for _, row in df.iterrows():
        due = row.get("next_review_due")
        if due:
            try:
                if datetime.strptime(due, "%Y-%m-%d").date() < today:
                    overdue += 1
            except Exception:
                pass
    return {
        "total": len(df),
        "approved": int((df["status"] == "Approved").sum()),
        "draft": int((df["status"] == "Draft").sum()),
        "in_review": int((df["status"] == "In Review").sum()),
        "overdue": overdue,
    }


def export_document_bundle(document_id: str) -> Tuple[str, bytes]:
    current = get_document_with_content(document_id)
    if not current:
        raise ValueError("Document not found")
    versions = list_document_versions(document_id)
    approvals = list_document_approvals(document_id)
    reviews = list_document_reviews(document_id)
    bio = BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("current_document.md", current.get("content_md", ""))
        z.writestr("document_metadata.json", json.dumps({k: v for k, v in current.items() if k != "content_md"}, indent=2, default=str))
        z.writestr("versions.csv", versions.to_csv(index=False))
        z.writestr("approvals.csv", approvals.to_csv(index=False))
        z.writestr("reviews.csv", reviews.to_csv(index=False))
    safe_name = current["title"].replace(" ", "_").replace("/", "-")
    return f"{safe_name}_document_bundle.zip", bio.getvalue()


def render_document_governance_tab(tenant_id: str, auth: Dict[str, Any], role: str):
    st.header("FedRAMP Document Governance")
    metrics = document_dashboard_metrics(tenant_id)
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Controlled Docs", metrics["total"])
    m2.metric("Approved", metrics["approved"])
    m3.metric("Draft", metrics["draft"])
    m4.metric("In Review", metrics["in_review"])
    m5.metric("Overdue Reviews", metrics["overdue"])

    docs_df = list_documents(tenant_id)
    work = st.tabs(["Library", "Create Template", "Edit / Version", "Approvals", "Reviews", "Export"])

    with work[0]:
        family_filter = st.selectbox("Family Filter", ["(All)"] + [x[0] for x in FEDRAMP_DOCUMENT_FAMILIES], key="doc_family_filter")
        status_filter = st.selectbox("Status Filter", ["(All)"] + DOCUMENT_STATUSES, key="doc_status_filter")
        view_df = docs_df.copy()
        if not view_df.empty and family_filter != "(All)":
            view_df = view_df[view_df["family_id"] == family_filter]
        if not view_df.empty and status_filter != "(All)":
            view_df = view_df[view_df["status"] == status_filter]
        if not view_df.empty:
            view_df = view_df.copy()
            view_df["family_name"] = view_df["family_id"].apply(document_family_name)
            st.dataframe(view_df[["document_id", "family_id", "family_name", "doc_type", "title", "owner", "approver_title", "status", "updated_at", "next_review_due"]], use_container_width=True)
        else:
            st.info("No controlled documents yet for this tenant.")

    with work[1]:
        require_role(["SuperAdmin", "TenantAdmin"])
        company_name = tenant_name(tenant_id)
        family_id = st.selectbox("Family", [x[0] for x in FEDRAMP_DOCUMENT_FAMILIES], format_func=lambda x: f"{x} – {document_family_name(x)}", key="doc_create_family")
        doc_type = st.selectbox("Document Type", DOCUMENT_TYPES, key="doc_create_type")
        owner = st.text_input("Document Owner", value="Compliance", key="doc_create_owner")
        approver_name = st.text_input("Senior Management Approver Name", value="", key="doc_create_approver_name")
        approver_title = st.selectbox("Senior Management Approver Title", SENIOR_APPROVER_TITLES, key="doc_create_approver_title")
        review_frequency = st.selectbox("Review Frequency", REVIEW_FREQUENCIES, index=2, key="doc_create_review_frequency")
        default_title = f"{company_name} {document_family_name(family_id)} {doc_type}"
        title = st.text_input("Document Title", value=default_title, key="doc_create_title")
        description = st.text_area("Description", value=f"Controlled {doc_type.lower()} for FedRAMP {family_id} requirements.", key="doc_create_desc")
        generated = generate_document_template(family_id, doc_type, company_name, owner, approver_title)
        content = st.text_area("Initial Content (Markdown)", value=generated, height=520, key="doc_create_content")
        if st.button("Create Controlled Document", key="doc_create_btn"):
            doc_id = create_document_record(tenant_id, family_id, doc_type, title, description, owner, approver_name, approver_title, review_frequency, auth["email"], content)
            st.success(f"Document created: {doc_id}")
            st.rerun()

    with work[2]:
        require_role(["SuperAdmin", "TenantAdmin"])
        if docs_df.empty:
            st.info("Create a controlled document first.")
        else:
            selected_id = st.selectbox("Select Document", docs_df["document_id"].tolist(), format_func=lambda x: f"{x} – {docs_df.loc[docs_df.document_id == x, 'title'].iloc[0]}", key="doc_edit_select")
            current = get_document_with_content(selected_id)
            if current:
                st.caption(f"Current Version: {current.get('version_label') or 'n/a'} • Status: {current.get('status')} • Owner: {current.get('owner')}")
                updated_content = st.text_area("Editable Markdown", value=current.get("content_md") or "", height=560, key="doc_edit_content")
                change_summary = st.text_input("Change Summary", value="Updated content and operating procedures.", key="doc_edit_summary")
                major = st.checkbox("Major Version", value=True, key="doc_edit_major")
                c1, c2 = st.columns(2)
                if c1.button("Save New Version", key="doc_save_version"):
                    ver = save_document_version(selected_id, updated_content, change_summary, auth["email"], major=major)
                    st.success(f"Saved {ver}")
                    st.rerun()
                if c2.button("Preview Current Markdown", key="doc_preview_markdown"):
                    st.markdown(updated_content)
                versions_df = list_document_versions(selected_id)
                st.subheader("Version History")
                st.dataframe(versions_df, use_container_width=True)

    with work[3]:
        if docs_df.empty:
            st.info("Create a controlled document first.")
        else:
            selected_id = st.selectbox("Document for Approval", docs_df["document_id"].tolist(), format_func=lambda x: f"{x} – {docs_df.loc[docs_df.document_id == x, 'title'].iloc[0]}", key="doc_approval_select")
            current = get_document_with_content(selected_id)
            approvals_df = list_document_approvals(selected_id)
            if current:
                st.caption(f"Current Version: {current.get('version_label') or 'n/a'} • Status: {current.get('status')} • Assigned Approver: {current.get('approver_name') or 'Not assigned'}")
                submitter_can_edit = role in ("SuperAdmin", "TenantAdmin")
                approver_name = st.text_input("Approver Name", value=current.get("approver_name") or "", key="doc_submit_approver_name")
                approver_title = st.selectbox(
                    "Approver Title",
                    SENIOR_APPROVER_TITLES,
                    index=SENIOR_APPROVER_TITLES.index(current.get("approver_title")) if current.get("approver_title") in SENIOR_APPROVER_TITLES else 0,
                    key="doc_submit_approver_title",
                )
                if submitter_can_edit and st.button("Submit Current Version for Approval", key="doc_submit_btn"):
                    approval_id = submit_document_for_approval(selected_id, auth["email"], approver_name or auth["display_name"], approver_title)
                    st.success(f"Approval request created: {approval_id}")
                    st.rerun()
                st.subheader("Approval Requests")
                st.dataframe(approvals_df, use_container_width=True)
                if not approvals_df.empty and role == "SuperAdmin":
                    pending_df = approvals_df[approvals_df["status"] == "Pending"]
                    if not pending_df.empty:
                        pending_id = st.selectbox("Pending Approval", pending_df["approval_id"].tolist(), key="doc_pending_select")
                        decision_notes = st.text_area("Decision Notes", value="Reviewed for FedRAMP governance sufficiency.", key="doc_decision_notes")
                        c1, c2 = st.columns(2)
                        if c1.button("Approve", key="doc_approve_btn"):
                            decide_document_approval(pending_id, auth["display_name"], "Senior Management Representative", True, decision_notes)
                            st.success("Document approved.")
                            st.rerun()
                        if c2.button("Reject", key="doc_reject_btn"):
                            decide_document_approval(pending_id, auth["display_name"], "Senior Management Representative", False, decision_notes)
                            st.warning("Document sent back to draft.")
                            st.rerun()

    with work[4]:
        if docs_df.empty:
            st.info("Create a controlled document first.")
        else:
            selected_id = st.selectbox("Document for Review Log", docs_df["document_id"].tolist(), format_func=lambda x: f"{x} – {docs_df.loc[docs_df.document_id == x, 'title'].iloc[0]}", key="doc_review_select")
            current = get_document_with_content(selected_id)
            reviewer_name = st.text_input("Reviewer Name", value=auth["display_name"], key="doc_review_name")
            reviewer_role = st.text_input("Reviewer Role", value=role, key="doc_review_role")
            outcome = st.selectbox("Review Outcome", ["Reviewed", "No Changes Needed", "Requires Update", "Approved"], key="doc_review_outcome")
            notes = st.text_area("Review Notes", value="Periodic review completed.", key="doc_review_notes")
            if st.button("Log Review", key="doc_log_review_btn"):
                add_document_review(selected_id, current.get("current_version_id") if current else None, reviewer_name, reviewer_role, notes, outcome)
                st.success("Review logged.")
                st.rerun()
            st.subheader("Review History")
            st.dataframe(list_document_reviews(selected_id), use_container_width=True)

    with work[5]:
        if docs_df.empty:
            st.info("Create a controlled document first.")
        else:
            selected_id = st.selectbox("Document to Export", docs_df["document_id"].tolist(), format_func=lambda x: f"{x} – {docs_df.loc[docs_df.document_id == x, 'title'].iloc[0]}", key="doc_export_select")
            current = get_document_with_content(selected_id)
            if current:
                st.download_button("Download Current Markdown", (current.get("content_md") or "").encode("utf-8"), file_name=f"{current['title'].replace(' ', '_')}.md", mime="text/markdown", key="doc_download_md")
                bundle_name, bundle_bytes = export_document_bundle(selected_id)
                st.download_button("Download Governance Bundle", bundle_bytes, file_name=bundle_name, mime="application/zip", key="doc_download_bundle")
                st.code(current.get("content_md") or "")


def login_ui():
    st.title("NexlockAI Evidence Vault – Login")
    st.caption("Default SuperAdmin: admin@nexlock.ai • Password: ChangeMeNow! (change immediately)")
    email = st.text_input("Email", key="login_email")
    password = st.text_input("Password", type="password", key="login_password")
    if st.button("Sign in", key="login_signin"):
        auth = verify_login(email, password)
        if auth:
            st.session_state.auth = auth
            st.success("Signed in.")
            st.rerun()
        else:
            st.error("Invalid credentials.")

def topbar():
    a = st.session_state.auth
    c = st.columns([2,2,3,1])
    c[0].markdown(f"**User:** {a['display_name']}")
    c[1].markdown(f"**Role:** {a['role']}")
    c[2].markdown(f"**Tenant:** {a.get('tenant_id') or '—'}")
    if c[3].button("Sign out", key="topbar_signout"):
        st.session_state.auth = None
        st.rerun()



def render_audit_dashboard():
    st.title("📊 Security Audit Dashboard")

    # --- Load Data ---
    with connect() as conn:
        logins = pd.read_sql("SELECT * FROM login_events", conn)
        resets = pd.read_sql("SELECT * FROM password_resets", conn)

    if logins.empty:
        st.warning("No login data available")
        return

    # Convert timestamps
    logins["timestamp"] = pd.to_datetime(logins["timestamp"])
    resets["reset_at"] = pd.to_datetime(resets["reset_at"], errors="coerce")

    # --- Metrics ---
    total = len(logins)
    success = logins["success"].sum()
    failed = total - success

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Logins", total)
    col2.metric("Successful", int(success))
    col3.metric("Failed", int(failed))

    # --- Login Trend ---
    st.subheader("📈 Login Activity Over Time")
    trend = logins.groupby(logins["timestamp"].dt.date)["success"].count()
    st.line_chart(trend)

    # --- Failure Analysis ---
    st.subheader("🚨 Failed Login Attempts by User")
    failed_users = (
        logins[logins["success"] == 0]
        .groupby("user_id")
        .size()
        .sort_values(ascending=False)
    )
    st.bar_chart(failed_users)

    # --- High Risk Users ---
    st.subheader("⚠️ High Risk Accounts (Multiple Failures)")
    risky = failed_users[failed_users >= 5]
    st.dataframe(risky.reset_index().rename(columns={0: "failed_attempts"}))

    # --- Password Resets ---
    st.subheader("🔐 Recent Password Resets")
    if not resets.empty:
        st.dataframe(resets.sort_values("reset_at", ascending=False))
    else:
        st.info("No password resets recorded")

    # --- Full Audit Log ---
    st.subheader("📜 Full Login Audit Log")
    st.dataframe(logins.sort_values("timestamp", ascending=False))

    # --- Export ---
    st.subheader("⬇️ Export Logs")
    csv = logins.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download Login Audit CSV",
        csv,
        "login_audit.csv",
        "text/csv"
    )

def main():
    st.set_page_config("NexlockAI Multi-Tenant Evidence Vault", layout="wide")
    init_db()

    if "auth" not in st.session_state or not st.session_state.auth:
        login_ui()
        return

    topbar()
    auth = st.session_state.auth
    role = auth["role"]

    if role == "SuperAdmin":
        tdf = list_tenants()
        tenant_id = st.selectbox("Working Tenant", tdf["tenant_id"].tolist(), key="working_tenant",
                                format_func=lambda x: f"{x} – {tdf.loc[tdf.tenant_id==x,'tenant_name'].iloc[0]}")
    else:
        if not auth.get("tenant_id"):
            st.error("Your user is not assigned to a tenant.")
            return
        tenant_id = auth["tenant_id"]

    tabs = st.tabs([
        "Dashboard","Upload","Evidence","PKI Signatures","TSA",
        "Exceptions","POA&M","Evidence Diff","Document Governance", "Security Aidt", "Trust Center","Admin","Auditor Exports"
    ])

    # Dashboard
    with tabs[0]:
        st.header("Control Coverage")
        lookback = st.number_input("Lookback days", min_value=7, max_value=365, value=90, step=1, key="dash_lookback")
        st.dataframe(pd.DataFrame(derive_control_status(tenant_id, int(lookback))), use_container_width=True)

    # Upload
    with tabs[1]:
        require_role(["SuperAdmin","TenantAdmin"])
        st.header("Upload Evidence Artifact")
        control_id = st.selectbox("Control", [c for c,_ in CONTROLS], format_func=lambda x: f"{x} – {control_name(x)}", key="upload_control")
        cols = st.columns(3)
        owner = cols[0].text_input("Owner", value="Compliance", key="upload_owner")
        artifact_type = cols[1].selectbox("Artifact Type", ["Policy","Procedure","Log","Report","Ticket","Screenshot","Export","Other"], key="upload_artifact_type")
        source_system = cols[2].text_input("Source System", value="NexlockAI", key="upload_source_system")
        dcols = st.columns(2)
        ps = dcols[0].date_input("Period Start", key="upload_period_start")
        pe = dcols[1].date_input("Period End", key="upload_period_end")
        artifact_name = st.text_input("Artifact Name", value=f"{control_id} Evidence", key="upload_artifact_name")
        notes = st.text_area("Notes / Context", key="upload_notes")
        f = st.file_uploader("Select file", key="upload_file")
        if f is not None:
            b = f.getvalue()
            h = sha256_bytes(b)
            st.info(f"SHA-256: {h}")
            safe = f"{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}_{f.name}"
            p = UPLOADS / safe
            p.write_bytes(b)
            if st.button("Commit to Vault", key="upload_commit"):
                with connect() as conn:
                    q(conn, """
                        INSERT INTO evidence(tenant_id,control_id,artifact_name,artifact_type,owner,period_start,period_end,source_system,file_path,sha256,notes,uploaded_by,uploaded_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (tenant_id,control_id,artifact_name,artifact_type,owner,str(ps),str(pe),source_system,str(p),h,notes,auth["email"],utcnow_iso()))
                    conn.commit()
                st.success("Evidence saved.")
                st.rerun()

    # Evidence
    with tabs[2]:
        st.header("Evidence Library")
        filt = st.selectbox("Filter Control", ["(All)"]+[c for c,_ in CONTROLS], key="evidence_filter")
        df = list_evidence(tenant_id, None if filt=="(All)" else filt)
        st.dataframe(df, use_container_width=True)
        if not df.empty:
            st.download_button("Download Manifest CSV", df.to_csv(index=False).encode("utf-8"), file_name=f"{tenant_id}_evidence_manifest.csv", mime="text/csv")

    # PKI Signatures
    with tabs[3]:
        st.header("PKI Verification (green/red badges)")
        if not CRYPTO_OK:
            st.warning("Install `cryptography` (included in requirements.txt) for in-app verification.")
        df = list_evidence(tenant_id)
        if df.empty:
            st.info("Upload evidence first.")
        else:
            eid = st.selectbox("Evidence", df["evidence_id"].tolist(), format_func=lambda x: f"{x} – {df.loc[df.evidence_id==x,'artifact_name'].iloc[0]} ({df.loc[df.evidence_id==x,'control_id'].iloc[0]})", key="sig_evidence")
            row = df[df.evidence_id==eid].iloc[0].to_dict()
            st.code(f"Artifact SHA-256: {row['sha256']}")
            signer = st.text_input("Signer", value="Compliance Owner", key="sig_signer")
            pub = st.text_area("Public Key PEM", height=140, key="sig_pub")
            sig = st.text_area("Signature Base64", height=120, key="sig_b64")

            c1,c2,c3 = st.columns(3)
            if c1.button("Save Signature", key="sig_save"):
                require_role(["SuperAdmin","TenantAdmin"])
                with connect() as conn:
                    q(conn, """
                        INSERT INTO evidence_signatures(evidence_id,signer,alg,public_key_pem,signature_b64,signed_at)
                        VALUES (?,?,?,?,?,?)
                    """, (int(eid), signer, "RSA-PSS-SHA256", pub, sig, utcnow_iso()))
                    conn.commit()
                st.success("Signature stored.")
                st.rerun()

            if c2.button("Verify", key="sig_verify"):
                ok,msg = verify_signature_rsapss_sha256(pub, row["sha256"], sig)
                st.markdown("### " + ("🟢 Verified" if ok else "🔴 Not Verified"))
                st.write(msg)

            if c3.button("Verify + Save Result", key="sig_verify_save"):
                require_role(["SuperAdmin","TenantAdmin"])
                ok,msg = verify_signature_rsapss_sha256(pub, row["sha256"], sig)
                st.markdown("### " + ("🟢 Verified" if ok else "🔴 Not Verified"))
                with connect() as conn:
                    q(conn, """
                        UPDATE evidence_signatures SET verified=?, verified_at=?, verify_message=?
                        WHERE signature_id = (SELECT signature_id FROM evidence_signatures WHERE evidence_id=? ORDER BY signed_at DESC LIMIT 1)
                    """, (1 if ok else 0, utcnow_iso(), msg, int(eid)))
                    conn.commit()
                st.success("Verification status saved.")

            st.divider()
            with connect() as conn:
                sdf = pd.read_sql_query("""
                    SELECT s.signature_id, s.evidence_id, e.control_id, e.artifact_name, s.signer, s.verified, s.signed_at, s.verified_at, s.verify_message
                    FROM evidence_signatures s JOIN evidence e ON e.evidence_id=s.evidence_id
                    WHERE e.tenant_id=? ORDER BY s.signed_at DESC
                """, conn, params=(tenant_id,))
            if not sdf.empty:
                sdf["badge"] = sdf["verified"].apply(lambda x: "🟢" if int(x)==1 else "🔴")
                st.dataframe(sdf[["badge","signature_id","evidence_id","control_id","artifact_name","signer","signed_at","verified_at","verify_message"]], use_container_width=True)

    # TSA
    with tabs[4]:
        st.header("Timestamp Tokens (TSA)")
        df = list_evidence(tenant_id)
        if df.empty:
            st.info("Upload evidence first.")
        else:
            eid = st.selectbox("Evidence (TSA)", df["evidence_id"].tolist(), format_func=lambda x: f"{x} – {df.loc[df.evidence_id==x,'artifact_name'].iloc[0]}", key="tsa_evidence")
            row = df[df.evidence_id==eid].iloc[0].to_dict()
            st.code(f"Artifact SHA-256: {row['sha256']}")
            tsa_type = st.selectbox("TSA Type", ["INTERNAL_TSA","RFC3161","OTS"], key="tsa_type")
            token = st.text_area("Token JSON", height=220, placeholder='{"payload":{...},"signature_b64":"..."}', key="tsa_token")
            if st.button("Store Token", key="tsa_store"):
                require_role(["SuperAdmin","TenantAdmin"])
                with connect() as conn:
                    q(conn, "INSERT INTO evidence_timestamps(evidence_id,tsa_type,token_json,created_at) VALUES (?,?,?,?)",
                      (int(eid), tsa_type, token, utcnow_iso()))
                    conn.commit()
                st.success("Token stored.")
                st.rerun()

            st.divider()
            st.subheader("Recent Tokens")
            with connect() as conn:
                tdf = pd.read_sql_query("""
                    SELECT t.timestamp_id, t.evidence_id, e.control_id, e.artifact_name, t.tsa_type, t.created_at
                    FROM evidence_timestamps t JOIN evidence e ON e.evidence_id=t.evidence_id
                    WHERE e.tenant_id=? ORDER BY t.created_at DESC
                """, conn, params=(tenant_id,))
            st.dataframe(tdf, use_container_width=True)

    # Exceptions
    with tabs[5]:
        st.header("Exceptions + Compensating Controls")
        can_edit = role in ("SuperAdmin","TenantAdmin")
        control_id = st.selectbox("Control (Exception)", [c for c,_ in CONTROLS], format_func=lambda x: f"{x} – {control_name(x)}", key="ex_control")
        desc = st.text_area("Exception Description", key="ex_desc")
        risk = st.selectbox("Risk Level", ["Low","Moderate","High"], key="ex_risk")
        comp = st.text_area("Compensating Controls", key="ex_comp")
        owner = st.text_input("Owner", value="Compliance", key="ex_owner")
        expires = st.date_input("Expires On", value=date.today()+timedelta(days=90), key="ex_expires")
        if can_edit and st.button("Create Exception", key="ex_create"):
            with connect() as conn:
                q(conn, """
                    INSERT INTO exceptions(tenant_id,control_id,description,risk_level,compensating_controls,owner,approval,expires_on,status,created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                """, (tenant_id,control_id,desc,risk,comp,owner,"",str(expires),"Open",utcnow_iso()))
                conn.commit()
            st.success("Exception created.")
            st.rerun()
        st.divider()
        with connect() as conn:
            exdf = pd.read_sql_query("SELECT * FROM exceptions WHERE tenant_id=? ORDER BY created_at DESC", conn, params=(tenant_id,))
        st.dataframe(exdf, use_container_width=True)

    # POA&M
    with tabs[6]:
        st.header("Auto-generate FedRAMP-style POA&M from Gaps")
        lookback = st.number_input("Lookback days for stale evidence", min_value=7, max_value=365, value=90, step=1, key="poam_lb")
        items = generate_poam_items(tenant_id, int(lookback))
        st.dataframe(pd.DataFrame(items), use_container_width=True)
        c1,c2,c3 = st.columns(3)
        if c1.button("Save POA&M to DB"):
            require_role(["SuperAdmin","TenantAdmin"])
            upsert_poam(tenant_id, items)
            st.success("POA&M saved.")
        if c2.button("Download POA&M XLSX"):
            xbytes = poam_to_xlsx_bytes(items)
            st.download_button("Download", xbytes, file_name=f"{tenant_id}_POAM.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        if c3.button("Show POA&M from DB"):
            with connect() as conn:
                pdf = pd.read_sql_query("SELECT * FROM poam_items WHERE tenant_id=? ORDER BY created_at DESC", conn, params=(tenant_id,))
            st.dataframe(pdf, use_container_width=True)

    # Evidence Diff
    with tabs[7]:
        st.header("Evidence Diff Across Quarters")
        year = st.number_input("Year", value=datetime.utcnow().year, min_value=2000, max_value=2100, step=1, key="diff_year")
        colA,colB = st.columns(2)
        qa = colA.selectbox("Quarter A", [1,2,3,4], index=0, key="diff_qa")
        qb = colB.selectbox("Quarter B", [1,2,3,4], index=1, key="diff_qb")
        a = summarize_quarter(tenant_id, int(year), int(qa))
        b = summarize_quarter(tenant_id, int(year), int(qb))
        st.subheader(f"Q{qa} Summary")
        st.dataframe(a, use_container_width=True)
        st.subheader(f"Q{qb} Summary")
        st.dataframe(b, use_container_width=True)
        st.subheader("Diff")
        d = diff_quarters(a,b)
        st.dataframe(d, use_container_width=True)
        st.download_button("Download Diff CSV", d.to_csv(index=False).encode("utf-8"), file_name=f"{tenant_id}_Q{qa}_Q{qb}_diff.csv", mime="text/csv")

    # Document Governance
    with tabs[8]:
        render_document_governance_tab(tenant_id, auth, role)

    # 🔐 Security Audit
    with tabs[9]:
        require_role(["SuperAdmin"])

        st.header("🔐 Security Audit Dashboard")

        days = st.slider("Lookback Days", 1, 90, 7, key="audit_days")

        with connect() as conn:
            logins = pd.read_sql_query("SELECT * FROM login_events", conn)
            resets = pd.read_sql_query("SELECT * FROM password_resets", conn)

        if logins.empty:
            st.warning("No login activity recorded yet.")
            st.stop()

        logins["timestamp"] = pd.to_datetime(logins["timestamp"])
        cutoff = datetime.utcnow() - timedelta(days=days)
        logins = logins[logins["timestamp"] >= cutoff]

        # --- Metrics
        total = len(logins)
        success = int(logins["success"].sum())
        failed = total - success

        c1, c2, c3 = st.columns(3)
        c1.metric("Total Attempts", total)
        c2.metric("Successful", success)
        c3.metric("Failed", failed)

        # --- Trend
        st.subheader("📈 Login Activity")
        trend = logins.groupby(logins["timestamp"].dt.date)["success"].count()
        st.line_chart(trend)

        # --- Failures
        st.subheader("🚨 Failed Attempts by User")
        failed_users = (
            logins[logins["success"] == 0]
            .groupby("user_id")
            .size()
            .sort_values(ascending=False)
        )
        st.bar_chart(failed_users)

        # --- Risk Detection
        st.subheader("⚠️ High Risk Accounts")
        risky = failed_users[failed_users >= 5]

        if not risky.empty:
            st.error("Multiple failed login attempts detected")
            st.dataframe(risky.reset_index().rename(columns={0: "failed_attempts"}))
        else:
            st.success("No high-risk patterns detected")

        # --- Password Resets
        st.subheader("🔑 Password Reset Activity")

        if not resets.empty:
            resets["reset_at"] = pd.to_datetime(resets["reset_at"], errors="coerce")
            st.dataframe(resets.sort_values("reset_at", ascending=False), use_container_width=True)
        else:
            st.info("No password resets recorded")

        # --- Full Log
        st.subheader("📜 Full Login Log")
        st.dataframe(
            logins.sort_values("timestamp", ascending=False),
            use_container_width=True
        )

        # --- Export
        csv = logins.to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download Audit Log",
            csv,
            "audit_log.csv",
            "text/csv",
            key="audit_export"
        )

    # Trust Center
    with tabs[10]:
        st.header("Trust Center Auto-Publish (wired to DB)")
        require_role(["SuperAdmin","TenantAdmin"])
        lb = st.number_input("Lookback days", min_value=7, max_value=365, value=90, step=1, key="tc_lb")
        if st.button("Publish trust_center_status.json", key="tc_publish"):
            out = publish_trust_center(tenant_id, int(lb))
            st.success(f"Published: {out}")
        if st.button("Export customers.json for token tiers", key="tc_export_customers"):
            out = export_customers_json(tenant_id)
            st.success(f"Exported: {out}")
        st.caption("Host trust_center/ as a static site. Use ?token=public or a customer token.")
        st.code(str(TRUST_CENTER / "index.html"))

    # Admin
    with tabs[11]:
        require_role(["SuperAdmin"])
        st.header("Admin: Tenants + Users + Trust Customers")
        st.subheader("Tenants")
        tdf = list_tenants()
        st.dataframe(tdf, use_container_width=True)
        with st.expander("Create Tenant"):
            tid = st.text_input("Tenant ID", value=f"tenant_{datetime.utcnow().strftime('%Y%m%d')}", key="admin_tenant_id")
            tname = st.text_input("Tenant Name", key="admin_tenant_name")
            if st.button("Create Tenant", key="admin_create_tenant"):
                with connect() as conn:
                    q(conn, "INSERT INTO tenants(tenant_id,tenant_name,created_at) VALUES (?,?,?)", (tid,tname,utcnow_iso()))
                    conn.commit()
                st.success("Tenant created.")
                st.rerun()

        st.subheader("Users")
        with connect() as conn:
            udf = pd.read_sql_query("SELECT user_id,email,display_name,role,tenant_id,is_active,created_at FROM users ORDER BY created_at DESC", conn)
        st.dataframe(udf, use_container_width=True)
        with st.expander("Create/Update User (MVP password)"):
            email = st.text_input("Email", key="admin_user_email")
            display = st.text_input("Display Name", key="admin_user_display")
            role_new = st.selectbox("Role", ["SuperAdmin","TenantAdmin","Auditor"], key="admin_user_role")
            tenant_pick = st.selectbox("Tenant (for TenantAdmin/Auditor)", ["(None)"] + tdf["tenant_id"].tolist(), key="admin_user_tenant")
            pwd = st.text_input("Temp Password", type="password", key="admin_user_pwd")
            active = st.checkbox("Active", value=True, key="admin_user_active")
            if st.button("Save User", key="admin_save_user"):
                if not email or not pwd:
                    st.error("Email + password required.")
                else:
                    email_l = email.strip().lower()
                    ph = hashlib.sha256((email_l + pwd).encode("utf-8")).hexdigest()
                    uid = "user_" + hashlib.md5(email_l.encode("utf-8")).hexdigest()[:10]
                    tenant_val = None if tenant_pick=="(None)" else tenant_pick
                    with connect() as conn:
                        q(conn, """
                            INSERT OR REPLACE INTO users(user_id,email,display_name,role,tenant_id,password_hash,is_active,created_at)
                            VALUES (?,?,?,?,?,?,?,?)
                        """, (uid,email_l,display or email_l,role_new,tenant_val,ph,1 if active else 0,utcnow_iso()))
                        conn.commit()
                    st.success("User saved.")
                    st.rerun()

        st.subheader("Trust Center Customers (DB)")
        tc_tenant = st.selectbox("Tenant for customers", tdf["tenant_id"].tolist(), format_func=lambda x: f"{x} – {tenant_name(x)}", key="admin_customer_tenant")
        with connect() as conn:
            cdf = pd.read_sql_query("SELECT * FROM trust_customers WHERE tenant_id=? ORDER BY created_at DESC", conn, params=(tc_tenant,))
        st.dataframe(cdf, use_container_width=True)
        with st.expander("Create Customer Token"):
            cid = st.text_input("Customer ID", value=f"cust_{datetime.utcnow().strftime('%H%M%S')}", key="admin_customer_id")
            cname = st.text_input("Customer Name", key="admin_customer_name")
            tier = st.selectbox("Tier", ["PUBLIC","NDA","ENTERPRISE"], key="admin_customer_tier")
            token = st.text_input("Token", value="tok_" + hashlib.md5((cid+utcnow_iso()).encode()).hexdigest()[:16], key="admin_customer_token")
            expires = st.text_input("Token Expires UTC (optional)", value="", key="admin_customer_expires")
            nda = st.text_input("NDA Accepted UTC (optional)", value="", key="admin_customer_nda")
            if st.button("Save Customer", key="admin_save_customer"):
                with connect() as conn:
                    q(conn, """
                        INSERT OR REPLACE INTO trust_customers(customer_id,tenant_id,customer_name,tier,token,token_expires_utc,nda_accepted_utc,created_at)
                        VALUES (?,?,?,?,?,?,?,?)
                    """, (cid,tc_tenant,cname,tier,token,expires or None,nda or None,utcnow_iso()))
                    conn.commit()
                st.success("Customer saved.")
                st.rerun()

    # Auditor Exports
    with tabs[12]:
        st.header("Auditor Export Bundles (ZIP per control)")
        control_id = st.selectbox("Control to Export", [c for c,_ in CONTROLS], format_func=lambda x: f"{x} – {control_name(x)}", key="export_ctrl")
        df = list_evidence(tenant_id, control_id)
        st.dataframe(df, use_container_width=True)
        if st.button("Build ZIP", key="audit_build_zip"):
            out = EXPORTS / f"{tenant_id}_{control_id}_evidence_bundle.zip"
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
                manifest = df.drop(columns=["file_path"]).to_dict(orient="records") if not df.empty else []
                z.writestr("manifest.json", json.dumps(manifest, indent=2))
                for _, r in df.iterrows():
                    fp = Path(r["file_path"])
                    if fp.exists():
                        z.write(fp, arcname=f"artifacts/{fp.name}")
            st.success(f"Created {out.name}")
            st.download_button("Download ZIP", out.read_bytes(), file_name=out.name, mime="application/zip")

if __name__ == "__main__":
    main()
