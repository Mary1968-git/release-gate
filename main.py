import re
from fastapi import FastAPI, Request

app = FastAPI()

# ============================================================
# Q1 — Release Gate
# ============================================================

SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def evaluate_release_gate(body: dict) -> dict:
    v = set()
    wf = body.get("workflow") or {}
    img = body.get("image") or {}
    perms = wf.get("permissions") or {}

    # 1. Exact least-privilege permissions (no extra keys)
    exact = (
        set(perms.keys()) == {"contents", "packages", "id-token"}
        and perms.get("contents") == "read"
        and perms.get("packages") == "write"
        and perms.get("id-token") == "none"
    )
    if not exact:
        v.add("EXCESS_PERMISSION")

    # 2. Unsafe PR trigger
    if wf.get("trigger") == "pull_request_target":
        v.add("UNSAFE_PR_TRIGGER")

    # 3. Tests / matrix / failFast
    if wf.get("testsPassed") is not True or wf.get("matrixComplete") is not True or wf.get("failFast") is not False:
        v.add("TESTS_INCOMPLETE")

    # 4. Action pinning (third-party must be full SHA)
    for a in wf.get("actions") or []:
        if a.get("owner") != "actions":
            if not SHA_RE.match(str(a.get("ref", ""))):
                v.add("MUTABLE_ACTION")

    # 5. Image hardening
    if img.get("multiStage") is not True:
        v.add("SINGLE_STAGE_IMAGE")
    if img.get("runsAsRoot") is True:
        v.add("ROOT_RUNTIME")
    if img.get("secretMode") in ("arg", "copy"):
        v.add("SECRET_IN_LAYER")
    if (img.get("criticalVulnerabilities") or 0) > 0:
        v.add("CRITICAL_CVE")
    if img.get("digestPinned") is not True:
        v.add("UNPINNED_IMAGE")

    # 6. Production extras
    if body.get("target") == "production":
        if not (body.get("event") == "push" and body.get("ref") == "refs/heads/main"):
            v.add("INVALID_PRODUCTION_REF")
        if wf.get("environmentApproval") is not True:
            v.add("APPROVAL_REQUIRED")

    violations = list(v)
    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }


@app.post("/release-gate")
async def release_gate(request: Request):
    body = await request.json()
    return evaluate_release_gate(body)


# ============================================================
# Q2 — LLM Action Firewall
# ============================================================

TENANT = "tenant-zwyfpd4"
EMAIL_DOMAIN = "notify-aq3oq1n.example"
ALLOWED_TOOLS = {"search", "lookup_record", "send_email", "render_html"}


def _r(decision, reason):
    return {"decision": decision, "reason": reason}


def _is_str(x):
    return isinstance(x, str)


def _html_safe(html: str) -> bool:
    h = html.lower()
    if "<script" in h:
        return False
    if "<iframe" in h:
        return False
    if "javascript:" in h:
        return False
    if re.search(r"\bon\w+\s*=", h):  # inline event handlers
        return False
    return True


def evaluate_firewall(body: dict) -> dict:
    # 1. Top-level schema
    if not isinstance(body, dict):
        return _r("block", "INVALID_SCHEMA")
    if body.get("provenance") not in ("trusted", "untrusted"):
        return _r("block", "INVALID_SCHEMA")
    if not isinstance(body.get("humanApproved"), bool):
        return _r("block", "INVALID_SCHEMA")

    action = body.get("action")
    if not isinstance(action, dict):
        return _r("block", "INVALID_SCHEMA")
    tool = action.get("tool")
    args = action.get("args")
    if not _is_str(tool) or not isinstance(args, dict):
        return _r("block", "INVALID_SCHEMA")

    # 2. Tool allowlist
    if tool not in ALLOWED_TOOLS:
        return _r("block", "TOOL_NOT_ALLOWED")

    # 3-7. Per-tool schema, then tenant/egress/approval/safety
    if tool == "search":
        if set(args.keys()) != {"query"}:
            return _r("block", "INVALID_SCHEMA")
        q = args.get("query")
        if not _is_str(q) or not (1 <= len(q) <= 200):
            return _r("block", "INVALID_SCHEMA")
        return _r("allow", "ALLOW")

    if tool == "lookup_record":
        if set(args.keys()) != {"tenantId", "recordId"}:
            return _r("block", "INVALID_SCHEMA")
        tid, rid = args.get("tenantId"), args.get("recordId")
        if not _is_str(tid) or not _is_str(rid) or len(rid) == 0:
            return _r("block", "INVALID_SCHEMA")
        if tid != TENANT:
            return _r("block", "TENANT_SCOPE")
        return _r("allow", "ALLOW")

    if tool == "send_email":
        if set(args.keys()) != {"to", "subject", "body"}:
            return _r("block", "INVALID_SCHEMA")
        to, subj, bod = args.get("to"), args.get("subject"), args.get("body")
        if not (_is_str(to) and _is_str(subj) and _is_str(bod)):
            return _r("block", "INVALID_SCHEMA")
        domain = to.rsplit("@", 1)[1] if "@" in to else ""
        if domain != EMAIL_DOMAIN:
            return _r("block", "EGRESS_DENIED")
        if body.get("humanApproved") is not True:
            return _r("block", "APPROVAL_REQUIRED")
        return _r("allow", "ALLOW")

    if tool == "render_html":
        if set(args.keys()) != {"html"}:
            return _r("block", "INVALID_SCHEMA")
        html = args.get("html")
        if not _is_str(html):
            return _r("block", "INVALID_SCHEMA")
        if not _html_safe(html):
            return _r("block", "UNSAFE_OUTPUT")
        return _r("allow", "ALLOW")

    return _r("block", "TOOL_NOT_ALLOWED")


@app.post("/action-firewall")
async def action_firewall(request: Request):
    body = await request.json()
    return evaluate_firewall(body)
# ============================================================
# Q3 — Terraform Plan Policy Gate
# ============================================================

TF_WORKSPACE = "prod-p3n39e"
TF_LABELS = {"owner": "student-qle1f", "environment": "production", "cost_center": "cc-4oaq"}
VALID_BACKENDS = {"gcs", "s3", "azurerm", "remote"}
PROTECTED_DELETE_TYPES = {"storage_bucket", "sql_database", "persistent_disk"}


def _tf(decision, reason):
    return {"decision": decision, "reason": reason}


def _provider_pinned(pv: str) -> bool:
    """True if exact or pessimistically pinned; False if unpinned."""
    s = pv.strip()
    # Unpinned markers
    if ">=" in s or "*" in s or "latest" in s.lower():
        return False
    # Pessimistic pin
    if s.startswith("~>"):
        return True
    # Exact: "6.2.1" or "= 6.2.1"
    body = s[1:].strip() if s.startswith("=") else s
    if re.fullmatch(r"\d+\.\d+\.\d+", body):
        return True
    return False


def evaluate_terraform(body: dict) -> dict:
    # ---- 1. Type validation ----
    if not isinstance(body, dict):
        return _tf("reject", "INVALID_PLAN")

    env = body.get("environment")
    state = body.get("state")
    pv = body.get("providerVersion")
    destroy_approved = body.get("destroyApproved")
    resource = body.get("resource")

    if not isinstance(env, str):
        return _tf("reject", "INVALID_PLAN")
    if not isinstance(state, dict):
        return _tf("reject", "INVALID_PLAN")
    if not isinstance(state.get("backend"), str) or not isinstance(state.get("locked"), bool):
        return _tf("reject", "INVALID_PLAN")
    if not isinstance(pv, str):
        return _tf("reject", "INVALID_PLAN")
    if not isinstance(destroy_approved, bool):
        return _tf("reject", "INVALID_PLAN")
    if not isinstance(resource, dict):
        return _tf("reject", "INVALID_PLAN")

    r_type = resource.get("type")
    r_action = resource.get("action")
    r_labels = resource.get("labels")
    r_secret = resource.get("secret")
    r_force = resource.get("forceDestroy")

    if not isinstance(r_type, str):
        return _tf("reject", "INVALID_PLAN")
    if r_action not in ("create", "update", "delete"):
        return _tf("reject", "INVALID_PLAN")
    if not isinstance(r_labels, dict):
        return _tf("reject", "INVALID_PLAN")
    # secret must be null or string
    if r_secret is not None and not isinstance(r_secret, str):
        return _tf("reject", "INVALID_PLAN")
    if not isinstance(r_force, bool):
        return _tf("reject", "INVALID_PLAN")

    # ---- 2. Environment exact match ----
    if env != TF_WORKSPACE:
        return _tf("reject", "ENVIRONMENT_MISMATCH")

    # ---- 3. State backend + locked ----
    if state.get("backend") not in VALID_BACKENDS or state.get("locked") is not True:
        return _tf("reject", "STATE_UNSAFE")

    # ---- 4. Provider pinning ----
    if not _provider_pinned(pv):
        return _tf("reject", "UNPINNED_PROVIDER")

    # ---- 5. Labels exact ----
    for k, val in TF_LABELS.items():
        if r_labels.get(k) != val:
            return _tf("reject", "MISSING_LABELS")

    # ---- 6. Secret ----
    if r_secret is not None:
        if not (isinstance(r_secret, str) and r_secret.startswith("secret://") and len(r_secret) > len("secret://")):
            return _tf("reject", "PLAINTEXT_SECRET")

    # ---- 7. Protected delete needs approval ----
    if r_action == "delete" and r_type in PROTECTED_DELETE_TYPES:
        if destroy_approved is not True:
            return _tf("reject", "DELETE_NOT_APPROVED")

    # ---- 8. Prod storage_bucket forceDestroy ----
    if r_type == "storage_bucket" and r_force is True:
        return _tf("reject", "FORCE_DESTROY")

    return _tf("approve", "APPROVE")


@app.post("/terraform/plan")
async def terraform_plan(request: Request):
    body = await request.json()
    return evaluate_terraform(body)

# ============================================================
# Health
# ============================================================

@app.get("/")
def root():
    return {"status": "ok", "endpoints": ["/release-gate", "/action-firewall", "/terraform/plan"]}
