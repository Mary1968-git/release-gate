import re
from fastapi import FastAPI, Request

app = FastAPI()

SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def evaluate(body: dict) -> dict:
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
    return evaluate(body)


@app.get("/")
def root():
    return {"status": "ok"}
