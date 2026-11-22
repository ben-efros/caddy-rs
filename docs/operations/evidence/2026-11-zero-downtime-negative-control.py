import os, socket, subprocess, time, threading, signal, json
# The binary is the one cargo built; override with CADDY_RS_BIN.
BIN=os.environ.get("CADDY_RS_BIN","caddy-rs"); CFG="/tmp/caddy-rs-zero-downtime-negative.Caddyfile"
PORT=18898; res={"opened":0,"reset":0,"refused":0,"errors":[]}
with open(CFG,"w") as f: f.write(f":{PORT} {{\n\trespond \"ok\" 200\n}}\n")
srv=subprocess.Popen([BIN,"run","--config",CFG,"--adapter","caddyfile"],
                     stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
time.sleep(3)
def holder():
    try:
        s=socket.create_connection(("127.0.0.1",PORT),timeout=5); res["opened"]+=1
        time.sleep(2); s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        if not s.recv(4096): res["reset"]+=1
    except ConnectionResetError: res["reset"]+=1
    except OSError as e: res["reset"]+=1; res["errors"].append(type(e).__name__)
def hammer(end):
    while time.time()<end:
        try:
            s=socket.create_connection(("127.0.0.1",PORT),timeout=1); s.close(); res["opened"]+=1
        except ConnectionRefusedError: res["refused"]+=1
        except OSError: pass
        time.sleep(0.005)
h=threading.Thread(target=holder); h.start()
t=threading.Thread(target=hammer,args=(time.time()+5,)); t.start()
time.sleep(1.5)
srv.kill()          # SIGKILL: no drain, no inheritance -- must show resets AND refusals
h.join(timeout=6); t.join(timeout=6)
try: srv.wait(timeout=5)
except: srv.kill()
print(json.dumps(res))
