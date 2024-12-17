import os
import sys
import threading
import time

import requests
from fake_useragent import UserAgent
from fastapi import FastAPI, Request
from fastapi.responses import Response
from tqdm import tqdm
from uvicorn import Config, Server

ua = UserAgent()

PORT = 37491


app = FastAPI()

@app.get("/")
async def root(request: Request):
    user_agent = request.headers.get("user-agent")

    code = 200
    if not all(c == 'F' for c in user_agent):
        code = 400

    return Response(status_code=code, content=str(user_agent).encode())

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
    r = os.system(u)
    if r != 0:
        print(f"UA2F failed with exit code {r}")
        exit(-1)


def setup_iptables():
    os.system(f"iptables -A OUTPUT -p tcp --dport {PORT} -j NFQUEUE --queue-num 10010")
    os.system(f"ip6tables -A OUTPUT -p tcp --dport {PORT} -j NFQUEUE --queue-num 10010")

def cleanup_iptables():
    os.system(f"iptables -D OUTPUT -p tcp --dport {PORT} -j NFQUEUE --queue-num 10010")
    os.system(f"ip6tables -D OUTPUT -p tcp --dport {PORT} -j NFQUEUE --queue-num 10010")

def assert_equal(actual, expected):
    if actual != expected:
        raise AssertionError(f"Assertion failed: Expected {expected!r}, but got {actual!r}")

if __name__ == "__main__":
    if os.name != 'posix':
        raise Exception("This script only supports Linux")

    if os.geteuid() != 0:
        raise Exception("This script requires root privileges")

    ua2f = sys.argv[1]

    setup_iptables()

    start_server()

    ua2f_thread = threading.Thread(target=start_ua2f, args=(ua2f,))
    ua2f_thread.daemon = True
    ua2f_thread.start()

    print(f"Starting UA2F: {ua2f}")

    time.sleep(3)

    for i in tqdm(range(1024)):
        nxt = ua.random
        response = requests.get(f"http://127.0.0.1:{PORT}", headers={
            "User-Agent": nxt
        })
        assert response.ok
        assert len(response.text) == len(nxt)

    for i in tqdm(range(4096)):
        nxt = ua.random
        response = requests.get(f"http://[::1]:{PORT}", headers={
            "User-Agent": nxt
        })
        assert response.ok
        assert len(response.text) == len(nxt)

    # clean
    cleanup_iptables()
