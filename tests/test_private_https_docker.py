"""Opt-in real Nginx/mTLS tests; no published ports, production keys or services."""

from pathlib import Path
import json
import os
import secrets
import shutil
import subprocess
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy/private_https"
pytestmark = pytest.mark.skipif(
    os.environ.get("GVAI_RUN_HTTPS_DOCKER") != "1",
    reason="Requires approved disposable official Nginx image and container-only test dependencies.",
)

BACKEND = """
import json, threading, time
from gvai.commercial_api_keys import CustomerApiKeys, InMemoryApiKeyStore
from gvai.commercial_http import create_server, PrivateHttpEndpoints
from gvai.commercial_identity import (
    CommercialAuthorizer, CommercialCapability, CommercialResourceKind,
    CommercialResourceOwnership,
)
from gvai.commercial_service import CommercialEvaluationService
from gvai.commercial_usage import CommercialUsage, InMemoryUsageStore
from gvai.postgresql_advisory import AdvisoryPilotUsage
from gvai.evaluation import evaluate_request

class Ownership:
    def lookup(self, resource):
        tenant = {'project-a':'tenant-a', 'project-b':'tenant-b'}.get(resource)
        return None if tenant is None else CommercialResourceOwnership(
            resource, tenant, CommercialResourceKind.EVALUATION)

keys = CustomerApiKeys(InMemoryApiKeyStore(), verifier_secret=b'disposable-verifier-only-32bytes!!')
records = {}
for name, tenant in [('a','tenant-a'),('b','tenant-b')]:
    issued = keys.issue(tenant_id=tenant, principal_id='principal-'+name,
        capabilities=frozenset(CommercialCapability), expires_at=int(time.time())+3600)
    records[name] = issued.take_secret()
historical = CustomerApiKeys(keys._store, verifier_secret=b'disposable-verifier-only-32bytes!!',
                            clock=lambda: time.time()-120)
records['expired'] = historical.issue(tenant_id='tenant-a',principal_id='principal-a',
    capabilities=frozenset(CommercialCapability),expires_at=int(time.time())-60).take_secret()
issued = keys.issue(tenant_id='tenant-a',principal_id='principal-a',
    capabilities=frozenset(CommercialCapability),expires_at=int(time.time())+3600)
records['revoked']=issued.take_secret()
keys.revoke(issued.key_id)
authorizer = CommercialAuthorizer(keys, Ownership())
usage = CommercialUsage(authorizer, InMemoryUsageStore({'tenant-a':100,'tenant-b':100}))
def evaluator(request):
    with open('/test/evaluations','a') as stream: stream.write('evaluated\\n')
    return evaluate_request(request)
def summary(credential, resource):
    identity=keys.verify(credential)
    if (identity is None or CommercialCapability.READ_USAGE not in identity.capabilities
        or not authorizer.authorize(credential, CommercialCapability.EVALUATE, resource)):
        return None
    return AdvisoryPilotUsage(100,0,0,0,0)
server=create_server(CommercialEvaluationService(usage,evaluator=evaluator),port=8080,
    private_endpoints=PrivateHttpEndpoints(summary,lambda:True))
with open('/test/keys.json','w') as stream: json.dump(records,stream)
server.serve_forever()
"""

REQUEST = """
import http.client,json,ssl,sys
data=json.load(sys.stdin)
context=ssl.create_default_context(cafile='/test/ca.pem')
context.minimum_version=ssl.TLSVersion[data.get('minimum','TLSv1_2')]
context.maximum_version=ssl.TLSVersion[data.get('maximum','MAXIMUM_SUPPORTED')]
if data.get('client','client'):
    name=data.get('client','client')
    context.load_cert_chain('/test/'+name+'.pem','/test/'+name+'-key.pem')
connection=http.client.HTTPSConnection(data.get('host','localhost'),8443,timeout=5,context=context)
headers=data.get('headers',{})
if data.get('key'):
    headers['Authorization']='Bearer '+json.load(open('/test/keys.json'))[data['key']]
body=data.get('body')
if isinstance(body,dict):
    body=json.dumps(body)
    headers['Content-Type']='application/json'
try:
    connection.request(data.get('method','GET'),data.get('path','/readyz'),body=body,headers=headers)
    response=connection.getresponse()
    print(json.dumps({'status':response.status,'body':response.read().decode(),
                      'headers':dict(response.getheaders())}))
except (ssl.SSLError,ConnectionError) as error:
    print(json.dumps({'tls_rejected':True,'kind':type(error).__name__,
                      'reason':getattr(error,'reason',None)}))
finally:
    connection.close()
"""


@pytest.fixture(scope="module")
def docker_https(tmp_path_factory):
    directory = tmp_path_factory.mktemp("gvai-real-https")
    os.chmod(directory, 0o700)
    container = "gvai-real-https-" + secrets.token_hex(6)
    created = False

    def docker(*args, **kwargs):
        result = subprocess.run(
            ["docker", *args], capture_output=True, text=True, timeout=180, **kwargs,
        )
        if result.returncode:
            pytest.fail("Disposable Docker operation failed: " + result.stderr[-4000:])
        return result

    def execute(script, data=None):
        return docker("exec", "-i", container, "python3", "-c", script,
                      input=None if data is None else json.dumps(data)).stdout

    def openssl(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=30)

    try:
        for name in ("ca", "untrusted"):
            openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=disposable-" + name, "-keyout", str(directory / (name + "-key.pem")),
                    "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                    "-out", str(directory / (name + ".pem")))
        for name, purpose, ca in (
            ("server", "serverAuth", "ca"), ("client", "clientAuth", "ca"),
            ("untrusted-client", "clientAuth", "untrusted"),
        ):
            openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                    "-keyout", str(directory / (name + "-key.pem")), "-out", str(directory / (name + ".csr")))
            ext = directory / (name + ".ext")
            ext.write_text(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                "subjectAltName=DNS:localhost\nextendedKeyUsage=" + purpose + "\n"
            )
            openssl("x509", "-req", "-in", str(directory / (name + ".csr")),
                    "-CA", str(directory / (ca + ".pem")), "-CAkey", str(directory / (ca + "-key.pem")),
                    "-CAcreateserial", "-days", "1", "-extfile", str(ext),
                    "-out", str(directory / (name + ".pem")))
        for path in directory.iterdir():
            path.chmod(0o600)
        docker("run", "--detach", "--pull=never", "--name", container, "--entrypoint", "sleep",
               "--security-opt", "no-new-privileges:true", "--memory", "768m", "--pids-limit", "128",
               "nginx:stable", "infinity")
        created = True
        docker("exec", container, "sh", "-c",
               "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 systemd")
        docker("network", "disconnect", "bridge", container)
        info = json.loads(docker("inspect", container).stdout)[0]
        assert not info["HostConfig"]["PortBindings"]
        assert not info["NetworkSettings"]["Networks"]
        docker("exec", container, "mkdir", "-p", "/test", "/opt/gvai/current", "/opt/gvai/venv/bin",
               "/etc/gvai-ingress", "/run/gvai-ingress", "/var/log/gvai-ingress",
               "/etc/gvai-runtime", "/etc/gvai-operator", "/var/lib/gvai-operator")
        docker("cp", str(ROOT / "gvai"), container + ":/opt/gvai/current/gvai")
        docker("cp", str(ROOT / "deploy"), container + ":/opt/gvai/current/deploy")
        # CA private keys never enter the disposable server.
        for name in ("ca.pem", "server.pem", "server-key.pem", "client.pem", "client-key.pem",
                     "untrusted-client.pem", "untrusted-client-key.pem"):
            docker("cp", str(directory / name), container + ":/test/" + name)
        docker("exec", container, "sh", "-c",
               "cp /test/server.pem /etc/gvai-ingress/server-chain.pem; "
               "cp /test/server-key.pem /etc/gvai-ingress/server-key.pem; "
               "cp /test/ca.pem /etc/gvai-ingress/client-ca.pem; "
               "ln -s /usr/bin/python3 /opt/gvai/venv/bin/python; "
               "groupadd gvai-api; useradd -g gvai-api -s /usr/sbin/nologin gvai-api; "
               "groupadd gvai-proxy; useradd -g gvai-proxy -s /usr/sbin/nologin gvai-proxy; "
               "chown -R gvai-proxy:gvai-proxy /run/gvai-ingress /var/log/gvai-ingress /etc/gvai-ingress; "
               "chmod 700 /run/gvai-ingress /var/log/gvai-ingress; "
               "chmod 750 /etc/gvai-ingress; chmod 640 /etc/gvai-ingress/*; "
               "chown gvai-api:gvai-api /test; chmod 700 /test; "
               "chown -R root:root /opt/gvai/current; "
               "chmod -R go-w /opt/gvai/current; "
               "chmod 700 /etc/gvai-runtime /etc/gvai-operator /var/lib/gvai-operator")
        # Original configuration and non-root executable path, not a rendered proxy.
        validated = docker("exec", "--user", "gvai-proxy", container, "/usr/sbin/nginx", "-t",
                           "-c", "/opt/gvai/current/deploy/private_https/nginx.conf")
        assert "test is successful" in validated.stderr
        execute("from pathlib import Path; Path('/test/backend.py').write_text(" + repr(BACKEND) + ")")
        docker("exec", "--detach", "--user", "gvai-api", "--env", "PYTHONPATH=/opt/gvai/current",
               "--env", "PYTHONDONTWRITEBYTECODE=1", container,
               "sh", "-c", "python3 /test/backend.py >/test/backend.log 2>&1")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if execute("from pathlib import Path; print(Path('/test/keys.json').exists())").strip() == "True":
                break
            time.sleep(0.05)
        else:
            pytest.fail("Disposable advisory backend did not become ready.")
        docker("exec", "--detach", "--user", "gvai-proxy", container, "/usr/sbin/nginx",
               "-c", "/opt/gvai/current/deploy/private_https/nginx.conf", "-g", "daemon off;")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = execute(
                "import socket; s=socket.socket(); print(s.connect_ex(('127.0.0.1',8443))); s.close()")
            if result.strip() == "0":
                break
            time.sleep(0.05)
        else:
            pytest.fail("Disposable real Nginx did not become ready.")
        print(docker("exec", container, "nginx", "-v").stderr.strip())
        print(docker("exec", container, "systemd-analyze", "--version").stdout.splitlines()[0])
        execute(
            "from pathlib import Path; p=Path('/opt/gvai/current/deploy/private_https/nginx.conf'); "
            "data=p.read_text(); "
            "data='\\n'.join(line for line in data.splitlines() "
            "if not any(name in line for name in ['fastcgi_temp_path','uwsgi_temp_path','scgi_temp_path'])); "
            "p.with_name('pre-fix.conf').write_text(data+'\\n')"
        )

        class Services:
            def request(self, **data):
                # Shared source bucket: let each independent assertion begin with capacity.
                time.sleep(0.55)
                return json.loads(execute(REQUEST, data))

            def execute(self, script):
                return execute(script)

            def docker(self, *args):
                return docker(*args)

            name = container

        yield Services()
    finally:
        if created:
            docker("rm", "--force", container)
            assert not docker("ps", "-a", "--filter", "name=^/" + container + "$",
                              "--format", "{{.Names}}").stdout.strip()
        shutil.rmtree(directory)


def payload(request="request"):
    return {
        "version": "v1", "request_id": request, "resource_id": "project-a",
        "telemetry": {
            "token_delta": 100, "tool_calls_delta": 1, "error_delta": 0,
            "repeated_action_delta": 0, "recursion_depth": 0,
        }, "reported_effects": [],
    }


@pytest.mark.parametrize("version", ["TLSv1_2", "TLSv1_3"])
def test_real_docker_valid_client_tls_versions(docker_https, version):
    result = docker_https.request(minimum=version, maximum=version)
    assert result.get("status") == 200, result
    assert json.loads(result["body"]) == {
        "status": "ready", "advisory_only": True, "enforcement_applied": False,
    }


@pytest.mark.parametrize("client", [None, "untrusted-client"])
def test_real_docker_missing_untrusted_certificate_denies(docker_https, client):
    before = docker_https.execute("from pathlib import Path; p=Path('/test/evaluations'); print(p.read_text() if p.exists() else '')")
    result = docker_https.request(client=client)
    assert result.get("tls_rejected") or result["status"] == 503
    after = docker_https.execute("from pathlib import Path; p=Path('/test/evaluations'); print(p.read_text() if p.exists() else '')")
    assert before == after


def test_real_docker_wrong_server_hostname_denies(docker_https):
    result = docker_https.request(host="127.0.0.1")
    assert result.get("tls_rejected") is True


@pytest.mark.parametrize("key", [None, "expired", "revoked"])
def test_real_docker_unauthorized_never_invokes_evaluator(docker_https, key):
    before = docker_https.execute("from pathlib import Path; p=Path('/test/evaluations'); print(p.read_text() if p.exists() else '')")
    result = docker_https.request(method="POST", path="/v1/evaluations", key=key, body=payload())
    assert result["status"] == (401 if key is None else 403)
    after = docker_https.execute("from pathlib import Path; p=Path('/test/evaluations'); print(p.read_text() if p.exists() else '')")
    assert after == before


def test_real_docker_tenant_usage_and_evaluation_isolation(docker_https):
    assert docker_https.request(path="/v1/usage/project-b", key="a")["status"] == 403
    assert docker_https.request(path="/v1/usage/project-a", key="a")["status"] == 200
    wrong = {**payload("cross-tenant"), "resource_id": "project-b"}
    assert docker_https.request(method="POST", path="/v1/evaluations", key="a", body=wrong)["status"] == 403
    result = docker_https.request(method="POST", path="/v1/evaluations", key="a", body=payload("valid"))
    assert result["status"] == 200
    evaluation = json.loads(result["body"])["evaluation"]
    assert evaluation["advisory_only"] is True and evaluation["enforcement_applied"] is False
    assert docker_https.request(method="POST", path="/v1/evaluations", key="a", body=payload("valid"))["status"] == 409


def test_real_docker_routes_body_limits_and_secret_redaction(docker_https):
    for path in ("/v1/provision", "/v1/keys", "/v1/suspend", "/readyz?canary-secret=yes"):
        result = docker_https.request(path=path, headers={"Authorization": "Bearer canary-secret"})
        assert result["status"] == 503
        assert "canary-secret" not in result["body"]
    result = docker_https.request(method="POST", path="/v1/evaluations", key="a", body="x" * 16385)
    assert result["status"] == 503
    bounded = json.dumps(payload("body-exact-limit"))
    bounded += " " * (16384 - len(bounded.encode("ascii")))
    assert len(bounded.encode("ascii")) == 16384
    assert docker_https.request(
        method="POST", path="/v1/evaluations", key="a", body=bounded,
        headers={"Content-Type": "application/json"},
    )["status"] == 200
    logs = docker_https.execute(
        "from pathlib import Path; print(Path('/test/backend.log').read_text()); "
        "print(Path('/var/log/gvai-ingress/access.log').read_text())")
    assert "canary-secret" not in logs and "/readyz" not in logs
    assert docker_https.execute(
        "import json; from pathlib import Path; logs=Path('/var/log/gvai-ingress/access.log').read_text()+"
        "Path('/test/backend.log').read_text(); print(any(v in logs for v in json.load(open('/test/keys.json')).values()))"
    ).strip() == "False"


def test_real_docker_forwarding_spoof_cannot_replace_customer_authority(docker_https):
    result = docker_https.request(
        path="/v1/usage/project-b", key="a",
        headers={
            "X-Forwarded-Proto": "http", "Forwarded": "for=spoof;proto=http",
            "X-Forwarded-For": "spoof", "X-Tenant-ID": "tenant-b",
            "X-Principal-ID": "principal-b", "X-Forwarded-Host": "attacker",
        },
    )
    assert result["status"] == 403
    assert docker_https.request(
        path="/v1/usage/project-a", key="a", headers={"X-Tenant-ID": "tenant-b"},
    )["status"] == 200


def test_real_docker_rate_limit(docker_https):
    time.sleep(3)
    results = json.loads(docker_https.execute(
        "import json; results=[]\n"
        "for _ in range(12):\n"
        " import subprocess\n"
        " result=subprocess.run(['python3','-c'," + repr(REQUEST) + "],input='{}',text=True,capture_output=True,check=True)\n"
        " results.append(json.loads(result.stdout)['status'])\n"
        "print(json.dumps(results))"
    ))
    assert 200 in results and 503 in results


def test_real_docker_no_external_backend_or_ingress_listener(docker_https):
    result = docker_https.execute(
        "import socket; from pathlib import Path\n"
        "lines=Path('/proc/net/tcp').read_text().splitlines()[1:]\n"
        "listeners=[line.split()[1] for line in lines if line.split()[3]=='0A']\n"
        "assert set(listeners)=={'0100007F:1F90','0100007F:20FB'},listeners\n"
        "print('Only8080and8443loopback')"
    )
    assert "Only8080and8443loopback" in result
    assert not json.loads(docker_https.docker("inspect", docker_https.name).stdout)[0]["NetworkSettings"]["Networks"]


def test_real_docker_systemd_units_executables_and_restriction_analysis(docker_https):
    base = "/opt/gvai/current/deploy/private_https/"
    verified = docker_https.docker(
        "exec", docker_https.name, "systemd-analyze", "verify",
        base + "gvai-advisory.service", base + "gvai-ingress.service",
    )
    assert verified.returncode == 0
    for unit in ("gvai-advisory.service", "gvai-ingress.service"):
        analysis = docker_https.docker(
            "exec", docker_https.name, "systemd-analyze", "security", "--offline=yes",
            "--no-pager", base + unit,
        )
        assert "NoNewPrivileges=" in analysis.stdout
        assert "ProtectSystem=" in analysis.stdout
        assert "IPAddressDeny=" in analysis.stdout
    assert docker_https.execute(
        "import os; print(all(os.access(p,os.X_OK) for p in "
        "['/usr/sbin/nginx','/opt/gvai/venv/bin/python']))"
    ).strip() == "True"


def test_real_docker_original_temp_paths_fail_nonroot(docker_https):
    result = subprocess.run([
        "docker", "exec", "--user", "gvai-proxy", docker_https.name, "/usr/sbin/nginx",
        "-t", "-c", "/opt/gvai/current/deploy/private_https/pre-fix.conf",
    ], capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert 'mkdir() "/var/cache/nginx/fastcgi_temp" failed (13: Permission denied)' in result.stderr


@pytest.mark.parametrize("account,forbidden", [
    ("gvai-api", ["/etc/gvai-operator", "/var/lib/gvai-operator", "/etc/gvai-ingress/server-key.pem"]),
    ("gvai-proxy", ["/etc/gvai-runtime", "/etc/gvai-operator", "/var/lib/gvai-operator", "/test/keys.json"]),
])
def test_real_docker_unprivileged_secret_custody(docker_https, account, forbidden):
    script = (
        "import os; from pathlib import Path\n"
        "assert os.geteuid()!=0\n"
        "assert all(not os.access(p,os.R_OK) for p in " + repr(forbidden) + ")\n"
        "assert not os.access('/opt/gvai/current/deploy/private_https/nginx.conf',os.W_OK)\n"
        "status=Path('/proc/self/status').read_text()\n"
        "assert 'NoNewPrivs:\\t1' in status\n"
        "assert 'CapEff:\\t0000000000000000' in status\n"
        "print('custody restrictions verified')"
    )
    result = docker_https.docker("exec", "--user", account, docker_https.name, "python3", "-c", script)
    assert "custody restrictions verified" in result.stdout


def test_real_docker_backend_outage_never_returns_success(docker_https):
    # Last test: terminate only the specifically discovered disposable backend PID.
    docker_https.execute(
        "import os,signal; from pathlib import Path\n"
        "matches=[]\n"
        "for path in Path('/proc').iterdir():\n"
        " if path.name.isdigit():\n"
        "  try: command=(path/'cmdline').read_bytes().split(b'\\x00')\n"
        "  except (FileNotFoundError,PermissionError): continue\n"
        "  if command[:2]==[b'python3',b'/test/backend.py']: matches.append(int(path.name))\n"
        "assert len(matches)==1,matches\n"
        "os.kill(matches[0],signal.SIGTERM)"
    )
    result = docker_https.request(method="POST", path="/v1/evaluations", key="a", body=payload("outage"))
    assert result["status"] == 503
    assert json.loads(result["body"])["error"]["code"] == "ingress_unavailable"
