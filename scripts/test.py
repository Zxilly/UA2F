import atexit
import http.server
import json
import logging
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

import requests
from fake_useragent import UserAgent
from tqdm import tqdm
from fastapi import FastAPI, Request
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from uvicorn import Config, Server

ua = UserAgent()

PORT = 37491

app = FastAPI()


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def catch_all(request: Request, path: str = ""):
    user_agent = request.headers.get("user-agent")

    if user_agent is None:
        # No UA header at all — that's fine, UA2F doesn't add one
        return Response(content="no-ua", status_code=200)

    if all(c == 'F' for c in user_agent) and len(user_agent) > 0:
        # UA was replaced with F's — success
        return Response(content=str(len(user_agent)).encode())

    # UA was NOT replaced — fail
    return Response(
        content=f"UA not mangled: {user_agent}",
        status_code=400
    )


def start_server():
    config4 = Config(app=app, host="127.0.0.1", port=PORT, access_log=False)
    config6 = Config(app=app, host="::1", port=PORT, access_log=False)
    server4 = Server(config4)
    server6 = Server(config6)
    t4 = threading.Thread(target=server4.run)
    t4.daemon = True
    t6 = threading.Thread(target=server6.run)
    t6.daemon = True
    t4.start()
    t6.start()


def start_ua2f(u: str):
    env = os.environ.copy()

    ua2f_abs_path = os.path.abspath(u)
    build_dir = os.path.dirname(ua2f_abs_path)

    print(f"Starting UA2F from build directory: {build_dir}")
    original_cwd = os.getcwd()
    os.chdir(build_dir)

    binary_name = os.path.basename(ua2f_abs_path)
    p = subprocess.Popen([f'./{binary_name}'], env=env, cwd=build_dir)

    os.chdir(original_cwd)

    def graceful_shutdown():
        try:
            p.terminate()
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()

    atexit.register(graceful_shutdown)
    return p


def setup_iptables():
    os.system(f"sudo iptables -A OUTPUT -p tcp --dport {PORT} -j NFQUEUE --queue-num 10010")
    os.system(f"sudo ip6tables -A OUTPUT -p tcp --dport {PORT} -j NFQUEUE --queue-num 10010")


def cleanup_iptables():
    os.system(f"sudo iptables -D OUTPUT -p tcp --dport {PORT} -j NFQUEUE --queue-num 10010")
    os.system(f"sudo ip6tables -D OUTPUT -p tcp --dport {PORT} -j NFQUEUE --queue-num 10010")


# ---------------------------------------------------------------------------
# Test scenarios
# ---------------------------------------------------------------------------

passed = 0
failed = 0


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
    else:
        failed += 1
        print(f"  FAIL: {name}: {detail}")


def test_basic_ua_replacement():
    """Basic GET with random User-Agent — UA should be replaced with F's."""
    print("[Test] Basic UA replacement (IPv4) ...")
    for i in tqdm(range(256), desc="  IPv4 GET"):
        nxt = ua.random
        r = requests.get(f"http://127.0.0.1:{PORT}/", headers={"User-Agent": nxt})
        check("ipv4_basic", r.ok and r.text == str(len(nxt)),
              f"status={r.status_code} body={r.text[:80]}")


def test_basic_ua_replacement_ipv6():
    """Basic GET over IPv6."""
    print("[Test] Basic UA replacement (IPv6) ...")
    for i in tqdm(range(256), desc="  IPv6 GET"):
        nxt = ua.random
        r = requests.get(f"http://[::1]:{PORT}/", headers={"User-Agent": nxt})
        check("ipv6_basic", r.ok and r.text == str(len(nxt)),
              f"status={r.status_code} body={r.text[:80]}")


def test_http_methods():
    """All common HTTP methods should have UA replaced."""
    print("[Test] HTTP methods ...")
    methods = {
        "GET": requests.get,
        "POST": requests.post,
        "PUT": requests.put,
        "DELETE": requests.delete,
        "PATCH": requests.patch,
        "OPTIONS": requests.options,
        "HEAD": requests.head,
    }
    for method_name, fn in methods.items():
        nxt = ua.random
        r = fn(f"http://127.0.0.1:{PORT}/method-test", headers={"User-Agent": nxt})
        if method_name == "HEAD":
            # HEAD has no body, just check status
            check(f"method_{method_name}", r.status_code == 200,
                  f"status={r.status_code}")
        else:
            check(f"method_{method_name}", r.ok,
                  f"status={r.status_code} body={r.text[:80]}")


def test_post_with_body():
    """POST with JSON body — UA in body should not be touched."""
    print("[Test] POST with body ...")
    nxt = ua.random
    body = {"data": "test", "fake_ua": "Mozilla/5.0 Fake"}
    r = requests.post(
        f"http://127.0.0.1:{PORT}/post-body",
        json=body,
        headers={"User-Agent": nxt}
    )
    check("post_body", r.ok and r.text == str(len(nxt)),
          f"status={r.status_code} body={r.text[:80]}")


def test_various_ua_lengths():
    """Test with different UA lengths — very short, medium, very long."""
    print("[Test] Various UA lengths ...")
    test_uas = [
        "A",                    # 1 char
        "AB",                   # 2 chars
        "x" * 10,               # 10 chars
        "x" * 100,              # 100 chars
        "x" * 500,              # 500 chars
        "x" * 2000,             # 2000 chars
    ]
    for test_ua in test_uas:
        r = requests.get(
            f"http://127.0.0.1:{PORT}/ua-length",
            headers={"User-Agent": test_ua}
        )
        check(f"ua_len_{len(test_ua)}", r.ok and r.text == str(len(test_ua)),
              f"len={len(test_ua)} status={r.status_code} body={r.text[:80]}")


def test_special_ua_chars():
    """UA with special characters — parentheses, semicolons, slashes, unicode."""
    print("[Test] Special characters in UA ...")
    test_uas = [
        "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
        "curl/7.68.0",
        "Wget/1.21",
        "python-requests/2.28.0",
        "MyApp/1.0 (contact: admin@example.com)",
        "Bot; +http://example.com/bot",
        "UA with spaces and\ttabs",
    ]
    for test_ua in test_uas:
        r = requests.get(
            f"http://127.0.0.1:{PORT}/special-ua",
            headers={"User-Agent": test_ua}
        )
        check(f"special_ua", r.ok and r.text == str(len(test_ua)),
              f"ua={test_ua[:30]} status={r.status_code} body={r.text[:80]}")


def test_keepalive_session():
    """Multiple requests on the same keep-alive connection."""
    print("[Test] Keep-alive session ...")
    session = requests.Session()
    for i in range(10):
        nxt = ua.random
        r = session.get(
            f"http://127.0.0.1:{PORT}/keepalive/{i}",
            headers={"User-Agent": nxt}
        )
        check(f"keepalive_{i}", r.ok and r.text == str(len(nxt)),
              f"status={r.status_code} body={r.text[:80]}")
    session.close()


def test_keepalive_ipv6():
    """Keep-alive over IPv6."""
    print("[Test] Keep-alive session (IPv6) ...")
    session = requests.Session()
    for i in range(10):
        nxt = ua.random
        r = session.get(
            f"http://[::1]:{PORT}/keepalive6/{i}",
            headers={"User-Agent": nxt}
        )
        check(f"keepalive6_{i}", r.ok and r.text == str(len(nxt)),
              f"status={r.status_code} body={r.text[:80]}")
    session.close()


def test_concurrent_connections():
    """Multiple concurrent connections from different threads."""
    print("[Test] Concurrent connections ...")
    errors = []

    def worker(thread_id):
        for i in range(20):
            nxt = ua.random
            try:
                r = requests.get(
                    f"http://127.0.0.1:{PORT}/concurrent/{thread_id}/{i}",
                    headers={"User-Agent": nxt},
                    timeout=10
                )
                if not r.ok or r.text != str(len(nxt)):
                    errors.append(f"thread={thread_id} i={i} status={r.status_code}")
            except Exception as e:
                errors.append(f"thread={thread_id} i={i} error={e}")

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    check("concurrent", len(errors) == 0,
          f"{len(errors)} errors: {errors[:3]}")


def test_different_paths():
    """Requests to various URL paths."""
    print("[Test] Different URL paths ...")
    paths = [
        "/",
        "/index.html",
        "/api/v1/users",
        "/deep/nested/path/to/resource",
        "/path?query=value&foo=bar",
        "/path-with-dashes",
        "/path_with_underscores",
    ]
    for path in paths:
        nxt = ua.random
        r = requests.get(
            f"http://127.0.0.1:{PORT}{path}",
            headers={"User-Agent": nxt}
        )
        check(f"path_{path[:20]}", r.ok and r.text == str(len(nxt)),
              f"path={path} status={r.status_code}")


def test_case_sensitivity():
    """Header name case variants — all should be mangled."""
    print("[Test] Header name case sensitivity ...")
    # requests normalizes header names, so we use a raw socket to send
    # case-variant header names
    test_cases = [
        ("User-Agent", "NormalCase/1.0"),
        ("user-agent", "lowercase/1.0"),
        ("USER-AGENT", "UPPERCASE/1.0"),
        ("User-agent", "MixedCase/1.0"),
    ]
    for header_name, ua_val in test_cases:
        raw_request = (
            f"GET /case-test HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{PORT}\r\n"
            f"{header_name}: {ua_val}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("127.0.0.1", PORT))
                s.sendall(raw_request.encode())
                response = b""
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data
            response_str = response.decode(errors="replace")
            ok = "200 OK" in response_str
            check(f"case_{header_name}", ok,
                  f"header={header_name} response={response_str[:100]}")
        except Exception as e:
            check(f"case_{header_name}", False, f"error={e}")


def test_large_headers():
    """Request with many extra headers — UA should still be mangled."""
    print("[Test] Large headers ...")
    nxt = ua.random
    headers = {"User-Agent": nxt}
    for i in range(30):
        headers[f"X-Custom-Header-{i}"] = f"value-{i}-{'x' * 50}"
    r = requests.get(
        f"http://127.0.0.1:{PORT}/large-headers",
        headers=headers
    )
    check("large_headers", r.ok and r.text == str(len(nxt)),
          f"status={r.status_code} body={r.text[:80]}")


def test_post_form_data():
    """POST with form-encoded body containing 'User-Agent' in values."""
    print("[Test] POST form data ...")
    nxt = ua.random
    r = requests.post(
        f"http://127.0.0.1:{PORT}/form-post",
        data={"username": "admin", "User-Agent": "FakeInBody", "password": "secret"},
        headers={"User-Agent": nxt}
    )
    check("form_post", r.ok and r.text == str(len(nxt)),
          f"status={r.status_code} body={r.text[:80]}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if os.name != 'posix':
        raise Exception("This script only supports Linux")

    if os.geteuid() != 0:
        raise Exception("This script requires root privileges")

    ua2f = sys.argv[1]

    setup_iptables()

    start_server()

    ua2f_process = start_ua2f(ua2f)

    print(f"Starting UA2F: {ua2f}")

    time.sleep(3)

    # Run all test scenarios
    test_basic_ua_replacement()
    test_basic_ua_replacement_ipv6()
    test_http_methods()
    test_post_with_body()
    test_various_ua_lengths()
    test_special_ua_chars()
    test_keepalive_session()
    test_keepalive_ipv6()
    test_concurrent_connections()
    test_different_paths()
    test_case_sensitivity()
    test_large_headers()
    test_post_form_data()

    # Summary
    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print(f"{'='*60}")

    print("Tests completed, shutting down UA2F gracefully...")

    try:
        ua2f_process.terminate()
        ua2f_process.wait(timeout=5)
        print("UA2F terminated gracefully")
    except subprocess.TimeoutExpired:
        print("UA2F didn't respond to SIGTERM, force killing...")
        ua2f_process.kill()

    # clean
    cleanup_iptables()

    if failed > 0:
        sys.exit(1)
