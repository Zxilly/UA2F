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

import requests
from fake_useragent import UserAgent
from tqdm import tqdm

ua = UserAgent()

PORT = 37491


class MyHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        user_agent = self.headers.get('User-Agent')

        # assert user_agent only contains F
        if not all([c == 'F' for c in user_agent]):
            self.send_response(400)
            logging.error(f"Invalid User-Agent: {user_agent}")
        else:
            self.send_response(200)
        self.end_headers()
        ua_len = len(user_agent)
        self.wfile.write(str(ua_len).encode())


def start_server():
    def serve_forever(httpd):
        with httpd:
            atexit.register(httpd.shutdown)
            httpd.serve_forever()

    ipv4_server = socketserver.TCPServer(
        ("", PORT),
        MyHandler,
        bind_and_activate=False
    )
    ipv4_server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ipv4_server.server_bind()
    ipv4_server.server_activate()

    ipv6_server = socketserver.TCPServer(
        ("::", PORT),
        MyHandler,
        bind_and_activate=False
    )
    ipv6_server.address_family = socket.AF_INET6
    ipv6_server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ipv6_server.server_bind()
    ipv6_server.server_activate()

    # Run servers in separate threads
    threading.Thread(target=serve_forever, args=(ipv4_server,), daemon=True).start()
    threading.Thread(target=serve_forever, args=(ipv6_server,), daemon=True).start()

    print(f"Serving on port {PORT} (IPv4 and IPv6)")


def start_ua2f(u: str):
    p = subprocess.Popen([u])
    atexit.register(lambda: p.kill())


# iptables 设置函数
def setup_iptables():
    os.system(f"sudo iptables -A OUTPUT -p tcp --dport {PORT} -j NFQUEUE --queue-num 10010")
    os.system(f"sudo ip6tables -A OUTPUT -p tcp --dport {PORT} -j NFQUEUE --queue-num 10010")


def cleanup_iptables():
    os.system(f"sudo iptables -D OUTPUT -p tcp --dport {PORT} -j NFQUEUE --queue-num 10010")
    os.system(f"sudo ip6tables -D OUTPUT -p tcp --dport {PORT} -j NFQUEUE --queue-num 10010")


if __name__ == "__main__":
    if os.name != 'posix':
        raise Exception("This script only supports Linux")

    if os.geteuid() != 0:
        raise Exception("This script requires root privileges")

    ua2f = sys.argv[1]

    setup_iptables()

    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()

    print(f"Starting server on port {PORT}")

    ua2f_thread = threading.Thread(target=start_ua2f, args=(ua2f,))
    ua2f_thread.daemon = True
    ua2f_thread.start()

    print(f"Starting UA2F: {ua2f}")

    time.sleep(3)

    for i in tqdm(range(2000)):
        nxt = ua.random
        response = requests.get(f"http://127.0.0.1:{PORT}", headers={
            "User-Agent": nxt
        })
        assert response.ok
        assert response.text == str(len(nxt))

    for i in tqdm(range(2000)):
        nxt = ua.random
        response = requests.get(f"http://[::1]:{PORT}", headers={
            "User-Agent": nxt
        })
        assert response.ok
        assert response.text == str(len(nxt))

    # clean
    cleanup_iptables()
