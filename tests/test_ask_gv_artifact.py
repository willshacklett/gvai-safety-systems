"""Public build and knowledge review checks; no provider network or credentials."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from scripts.prepare_public_site import PUBLIC_FILES, REPOSITORY_ROOT


def test_public_artifact_never_contains_server_key_or_backend(tmp_path):
    canary = "ask-gv-test-credential-never-publish-987654321"
    output = tmp_path / "site"
    subprocess.run([sys.executable, "scripts/prepare_public_site.py", "--output", str(output)],
                   cwd=REPOSITORY_ROOT, env={**os.environ, "OPENAI_API_KEY": canary}, check=True)
    assert {p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()} == set(PUBLIC_FILES)
    for p in output.rglob("*"):
        if p.is_file():
            assert canary.encode() not in p.read_bytes()
    public_text = "\n".join((output / f).read_text() for f in PUBLIC_FILES if f.endswith((".html", ".js", ".css")))
    assert "api.openai.com" not in public_text
    assert not re.search(r"sk-[A-Za-z0-9_-]{20,}", public_text)
    assert "window.ASK_GV_ENDPOINT = '';" in (output / "ask-gv-config.js").read_text()
    assert not (output / "ask-gv/server.mjs").exists()
    assert not (output / "ask-gv/facts.json").exists()
    assert not (output / ".env").exists()


def test_versioned_facts_keep_status_and_verification_limits_explicit():
    data = json.loads((REPOSITORY_ROOT / "ask-gv/facts.json").read_text())
    assert data["baseline"] == "23299020ea200e268a1d91aa591c49b8a6557ecb"
    assert data["version"] == "2026-11-12.v2"
    facts = {f["id"]: f for f in data["facts"]}
    assert set(facts) == {"technology", "status", "pilot", "pricing", "setup", "platform", "docs", "feedback"}
    for key, expected in {"technology": "experimental", "status": "No production readiness", "pilot": "do not authorize or stop execution", "pricing": "No approved public price", "setup": "expiry", "platform": "Planned", "docs": "offline evidence"}.items():
        assert expected in json.dumps(facts[key])
    assert len(data["facts"]) == len(set(facts))
