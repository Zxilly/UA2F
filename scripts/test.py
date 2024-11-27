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

ua = UserAgent()

PORT = 37491


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        user_agent = self.headers.get('User-Agent')

        if not all([c == 'F' for c in user_agent]):
            self.send_response(400)
            logging.error(f"Invalid User-Agent: {user_agent}")
        else:
            self.send_response(200)
        self.end_headers()
        ua_len = len(user_agent)
        self.wfile.write(str(ua_len).encode())

def run_server():
    ipv4_server_address = ('0.0.0.0', PORT)
    ipv4_httpd = HTTPServer(ipv4_server_address, Handler)

    ipv6_server_address = ('::', PORT)
    ipv6_httpd = HTTPServer(ipv6_server_address, Handler)

    print(f'Starting servers on port {PORT}...')

    ipv4_thread = threading.Thread(target=ipv4_httpd.serve_forever)
    ipv4_thread.daemon = True
    ipv4_thread.start()

    ipv6_thread = threading.Thread(target=ipv6_httpd.serve_forever)
    ipv6_thread.daemon = True
    ipv6_thread.start()


def start_ua2f(u: str):
    p = subprocess.Popen([u])
    atexit.register(lambda: p.kill())


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

    run_server()

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
