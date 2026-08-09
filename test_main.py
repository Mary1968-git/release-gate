from main import evaluate

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
    assert evaluate(SAFE)["violations"] == []


def test_multi_failure():
    bad = {**SAFE, "workflow": {**SAFE["workflow"]}, "image": {**SAFE["image"]}}
    bad["workflow"]["trigger"] = "pull_request_target"
    bad["workflow"]["failFast"] = True
    bad["image"]["runsAsRoot"] = True
    bad["image"]["secretMode"] = "arg"
    out = evaluate(bad)
    assert out["decision"] == "block"
    for code in ["UNSAFE_PR_TRIGGER", "TESTS_INCOMPLETE", "ROOT_RUNTIME", "SECRET_IN_LAYER"]:
        assert code in out["violations"]


def test_production_ref():
    prod = {**SAFE, "target": "production", "event": "push", "ref": "refs/heads/dev",
            "workflow": {**SAFE["workflow"], "environmentApproval": True}}
    assert "INVALID_PRODUCTION_REF" in evaluate(prod)["violations"]


def test_extra_permission_key():
    p = {**SAFE, "workflow": {**SAFE["workflow"],
         "permissions": {"contents": "read", "packages": "write", "id-token": "none", "actions": "write"}}}
    assert "EXCESS_PERMISSION" in evaluate(p)["violations"]
