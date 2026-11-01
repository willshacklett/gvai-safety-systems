from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy/private_https"
NGINX = shutil.which("nginx")
OPENSSL = shutil.which("openssl")
CONFIG = (DEPLOY / "nginx.conf").read_text()


def test_proxy_private_tls_and_no_plaintext_listener():
    assert "listen 127.0.0.1:8443 ssl default_server;" in CONFIG
    assert CONFIG.count("listen ") == 1
    assert "ssl_verify_client on;" in CONFIG
    assert "ssl_client_certificate /etc/gvai-ingress/client-ca.pem;" in CONFIG
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in CONFIG
    assert "ssl_session_tickets off;" in CONFIG
    assert "ssl_session_cache off;" in CONFIG
    assert "ssl_handshake_timeout" not in CONFIG
    assert "proxy_pass http://127.0.0.1:8080;" in CONFIG
    assert CONFIG.count("proxy_pass ") == 1


def test_proxy_forwarding_has_no_authentication_or_accounting_fallback():
    for directive in (
        "proxy_pass_request_headers off;", "proxy_set_header Authorization $http_authorization;",
        "proxy_set_header Host gvai-private-backend;", "proxy_set_header X-Forwarded-Proto https;",
        "proxy_set_header X-Forwarded-For $remote_addr;", 'proxy_set_header Forwarded "";',
        'proxy_set_header X-Forwarded-Host "";', "proxy_next_upstream off;",
        "proxy_cache off;", "proxy_intercept_errors off;", "proxy_request_buffering on;",
    ):
        assert directive in CONFIG
    for forbidden in ("auth_basic", "auth_request", "proxy_store", "proxy_cache_use_stale", "error_page 200"):
        assert forbidden not in CONFIG
    assert 'map "$request_method:$request_uri" $allowed_request' in CONFIG
    assert "default 0;" in CONFIG
    assert '"POST:/v1/evaluations" 1;' in CONFIG
    assert '"GET:/healthz" 1;' in CONFIG
    assert '"GET:/readyz" 1;' in CONFIG
    assert '"~^GET:/v1/usage/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" 1;' in CONFIG
    assert "if ($allowed_request = 0) { return 404; }" in CONFIG
    for path in ("/v1/provision", "/v1/keys", "/v1/suspend"):
        assert path not in CONFIG


def test_proxy_bounds_and_redacts_every_request_log():
    for directive in (
        "client_max_body_size 16384;", "large_client_header_buffers 4 4k;",
        "client_header_timeout 5s;", "client_body_timeout 5s;", "send_timeout 5s;",
        "worker_connections 128;", "keepalive_timeout 0;",
        "limit_req zone=per_client burst=4 nodelay;",
        "limit_conn total_connections 8;", "limit_conn per_client_connections 4;",
        "proxy_connect_timeout 1s;", "proxy_read_timeout 20s;",
        "error_log /dev/null crit;",
        "log_format redacted '$status $body_bytes_sent $request_time';",
        "access_log /var/log/gvai-ingress/access.log redacted;",
    ):
        assert directive in CONFIG
    log_format = CONFIG.split("log_format redacted ", 1)[1].split(";", 1)[0]
    assert set(log_format.strip("'").split()) == {"$status", "$body_bytes_sent", "$request_time"}
    assert "return 503" in CONFIG
    assert '"ingress_unavailable"' in CONFIG
    assert "Cache-Control no-store always;" in CONFIG
    assert "Strict-Transport-Security" in CONFIG


def test_database_configuration_never_opens_public_or_logs_parameters():
    config = (DEPLOY / "postgresql.conf").read_text()
    hba = (DEPLOY / "pg_hba.conf").read_text()
    rules = [line.split() for line in hba.splitlines() if line and not line.startswith("#")]
    assert "listen_addresses = '127.0.0.1'" in config
    assert "password_encryption = 'scram-sha-256'" in config
    assert rules == [
        ["local", "all", "postgres", "peer"],
        ["host", "gvai_staging", "gvai_runtime", "127.0.0.1/32", "scram-sha-256"],
        ["host", "gvai_staging", "gvai_owner", "127.0.0.1/32", "scram-sha-256"],
        ["local", "all", "all", "reject"],
        ["host", "all", "all", "0.0.0.0/0", "reject"],
        ["host", "all", "all", "::/0", "reject"],
    ]
    for directive in (
        "log_statement = 'none'", "log_min_error_statement = 'panic'",
        "log_parameter_max_length = 0", "log_parameter_max_length_on_error = 0",
        "log_destination = 'syslog'", "syslog_ident = 'gvai-private-postgres'",
    ):
        assert directive in config
    discard = (DEPLOY / "rsyslog-private-postgres.conf").read_text()
    assert 'if ($programname == "gvai-private-postgres")' in discard
    assert "stop" in discard


@pytest.mark.parametrize("name,account", [
    ("gvai-advisory.service", "gvai-api"), ("gvai-ingress.service", "gvai-proxy"),
])
def test_service_privilege_separation_and_resource_bounds(name, account):
    unit = (DEPLOY / name).read_text()
    for directive in (
        "User=" + account, "Group=" + account, "NoNewPrivileges=true",
        "ProtectSystem=strict", "ProtectHome=true", "PrivateTmp=true", "PrivateDevices=true",
        "CapabilityBoundingSet=\n", "AmbientCapabilities=\n", "IPAddressDeny=any",
        "IPAddressAllow=localhost", "RestrictAddressFamilies=AF_UNIX AF_INET",
        "UMask=0077", "Restart=on-failure", "StartLimitBurst=3",
        "KillMode=control-group", "LimitNOFILE=256",
    ):
        assert directive in unit
    assert "ExecReload" not in unit
    assert "password" not in unit.lower()
    assert "postgresql://" not in unit
    assert "gvai-operator" in unit
    assert "MemoryMax=" in unit and "TasksMax=" in unit
    if account == "gvai-api":
        assert "LoadCredential=runtime.json:/etc/gvai-runtime/runtime.json" in unit
        assert "--config %d/runtime.json serve" in unit
        assert "KillSignal=SIGTERM" in unit
        assert "check_ready.py" in unit
    else:
        assert "KillSignal=SIGQUIT" in unit
        assert "Requires=gvai-advisory.service" in unit
        assert "RuntimeDirectory=gvai-ingress" in unit
        assert "StandardError=null" in unit


@pytest.fixture
def readiness_module():
    spec = importlib.util.spec_from_file_location("gvai_test_readiness", DEPLOY / "check_ready.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("status,payload,expected", [
    (200, {"status": "ready", "advisory_only": True, "enforcement_applied": False}, 0),
    (503, {"status": "unavailable"}, 1),
    (200, {"status": "ready", "enforcement_applied": True}, 1),
    (200, {"status": "ready"}, 1),
    (200, "password-in-malformed-response", 1),
    (200, "x" * 1025, 1),
])
def test_readiness_check_never_accepts_success_shaped_uncertainty(
    readiness_module, monkeypatch, capsys, status, payload, expected,
):
    class Response:
        def __init__(self):
            self.status = status

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def read(self, maximum):
            raw = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
            return raw[:maximum]

    class Opener:
        def open(self, url, timeout):
            assert url == "http://127.0.0.1:8080/readyz" and timeout == 3
            return Response()

    monkeypatch.setattr(readiness_module, "build_opener", lambda *_args: Opener())
    assert readiness_module.check_ready(attempts=1) == expected
    assert "password" not in capsys.readouterr().err


def test_readiness_connection_failure_redacted(readiness_module, monkeypatch, capsys):
    class Opener:
        def open(self, *_args, **_kwargs):
            raise OSError("secret-database-password")

    monkeypatch.setattr(readiness_module, "build_opener", lambda *_args: Opener())
    assert readiness_module.check_ready(attempts=1) == 1
    assert capsys.readouterr().err == "GVAI private advisory readiness unavailable.\n"


@pytest.fixture
def real_proxy(tmp_path):
    if NGINX is None or OPENSSL is None:
        pytest.skip("Real Nginx/mTLS requires locally installed nginx and openssl; no proxy/TLS claim from static tests.")

    def openssl(*args):
        subprocess.run([OPENSSL, *args], check=True, capture_output=True, timeout=20)

    ca, ca_key = tmp_path / "ca.pem", tmp_path / "ca-key.pem"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=GVAI disposable test CA", "-keyout", str(ca_key), "-out", str(ca))
    for name, usage in (("server", "serverAuth"), ("client", "clientAuth")):
        key, request, cert = (tmp_path / (name + suffix) for suffix in ("-key.pem", ".csr", ".pem"))
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                "-keyout", str(key), "-out", str(request))
        extension = tmp_path / (name + ".ext")
        extension.write_text("subjectAltName=DNS:localhost\nextendedKeyUsage=" + usage + "\n")
        openssl("x509", "-req", "-in", str(request), "-CA", str(ca), "-CAkey", str(ca_key),
                "-CAcreateserial", "-days", "1", "-extfile", str(extension), "-out", str(cert))
    calls = []
    state = {"status": 200}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append((self.path, dict(self.headers)))
            body = b'{"advisory_only":true,"enforcement_applied":false}'
            self.send_response(state["status"])
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    backend = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=backend.serve_forever)
    thread.start()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    rendered = CONFIG.replace("/run/gvai-ingress", str(tmp_path / "run"))
    rendered = rendered.replace("/var/log/gvai-ingress", str(tmp_path))
    rendered = rendered.replace("/etc/gvai-ingress/server-chain.pem", str(tmp_path / "server.pem"))
    rendered = rendered.replace("/etc/gvai-ingress/server-key.pem", str(tmp_path / "server-key.pem"))
    rendered = rendered.replace("/etc/gvai-ingress/client-ca.pem", str(ca))
    rendered = rendered.replace("127.0.0.1:8443", "127.0.0.1:" + str(port))
    rendered = rendered.replace("127.0.0.1:8080", "127.0.0.1:" + str(backend.server_port))
    (tmp_path / "run").mkdir()
    config = tmp_path / "nginx.conf"
    config.write_text(rendered)
    process = None
    try:
        subprocess.run([NGINX, "-t", "-c", str(config)], check=True, capture_output=True, timeout=10)
        process = subprocess.Popen([NGINX, "-c", str(config), "-g", "daemon off;"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    break
            if process.poll() is not None:
                pytest.fail("Disposable nginx failed startup.")
            time.sleep(0.05)
        else:
            pytest.fail("Disposable nginx listener did not become ready.")

        def request(path, client=True, headers=None):
            context = ssl.create_default_context(cafile=str(ca))
            if client:
                context.load_cert_chain(str(tmp_path / "client.pem"), str(tmp_path / "client-key.pem"))
            connection = HTTPSConnection("localhost", port, timeout=3, context=context)
            try:
                connection.request("GET", path, headers=headers or {})
                response = connection.getresponse()
                return response.status, response.read()
            finally:
                connection.close()

        yield SimpleNamespace(request=request, calls=calls, state=state, log=tmp_path / "access.log")
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        backend.shutdown()
        backend.server_close()
        thread.join(timeout=2)


def test_real_mtls_and_forwarding_redaction(real_proxy):
    try:
        status, _ = real_proxy.request("/readyz", client=False)
        assert status != 200
    except ssl.SSLError:
        pass
    assert real_proxy.calls == []
    status, _ = real_proxy.request("/readyz", headers={
        "Authorization": "Bearer disposable-secret", "X-Forwarded-Proto": "http",
        "X-Forwarded-For": "untrusted", "Forwarded": "secret-spoof",
    })
    assert status == 200
    forwarded = real_proxy.calls[-1][1]
    assert forwarded["Authorization"] == "Bearer disposable-secret"
    assert forwarded["X-Forwarded-Proto"] == "https"
    assert forwarded["X-Forwarded-For"] == "127.0.0.1"
    assert "Forwarded" not in forwarded
    assert "disposable-secret" not in real_proxy.log.read_text()
    assert "/readyz" not in real_proxy.log.read_text()


def test_real_route_and_query_rejection(real_proxy):
    for path in ("/v1/provision", "/v1/keys", "/readyz?secret=value", "/v1/usage/a%2Fb"):
        status, body = real_proxy.request(path)
        assert status == 503
        assert b"value" not in body
    assert real_proxy.calls == []


def test_real_proxy_preserves_backend_denial_and_uncertainty(real_proxy):
    for status in (403, 409, 429, 503):
        real_proxy.state["status"] = status
        assert real_proxy.request("/readyz")[0] == status
        time.sleep(0.55)
    assert len(real_proxy.calls) == 4


def test_real_proxy_rate_limit_bounds_forwarding(real_proxy):
    statuses = [real_proxy.request("/readyz")[0] for _ in range(12)]
    assert 503 in statuses
    assert len(real_proxy.calls) < 12
