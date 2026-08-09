from main import evaluate_release_gate as evaluate, evaluate_firewall

SAFE = {
    "target": "preview", "event": "pull_request", "ref": "refs/heads/feature",
    "workflow": {
        "trigger": "pull_request",
        "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
        "testsPassed": True, "matrixComplete": True, "failFast": False,
        "actions": [{"owner": "actions", "name": "checkout", "ref": "v4"}],
    },
    "image": {"multiStage": True, "runsAsRoot": False, "secretMode": "none",
              "criticalVulnerabilities": 0, "digestPinned": True},
}


def test_safe_promotes():
    assert evaluate(SAFE)["decision"] == "promote"


def test_firewall_search_allow():
    out = evaluate_firewall({"provenance": "untrusted", "humanApproved": False,
                             "action": {"tool": "search", "args": {"query": "hi"}}})
    assert out == {"decision": "allow", "reason": "ALLOW"}


def test_firewall_tenant_scope():
    out = evaluate_firewall({"provenance": "trusted", "humanApproved": False,
                             "action": {"tool": "lookup_record",
                                        "args": {"tenantId": "wrong", "recordId": "r1"}}})
    assert out["reason"] == "TENANT_SCOPE"


def test_firewall_egress():
    out = evaluate_firewall({"provenance": "trusted", "humanApproved": True,
                             "action": {"tool": "send_email",
                                        "args": {"to": "a@evil.example", "subject": "s", "body": "b"}}})
    assert out["reason"] == "EGRESS_DENIED"
