import os, socket, subprocess, time, threading, sys, os, signal, json

CFG = "/tmp/caddy-rs-zero-downtime-probe.Caddyfile"
# The binary is the one cargo built; override with CADDY_RS_BIN.
BIN = os.environ.get("CADDY_RS_BIN", "caddy-rs")
PORT = 18899
results = {"opened": 0, "reset": 0, "refused": 0, "errors": []}
stop = threading.Event()

def holder(n):
    """Open a connection before the restart and keep it open, reading until closed."""
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    except OSError as e:
        results["errors"].append(f"holder{n} connect: {e}"); results["refused"] += 1; return
    results["opened"] += 1
    try:
        while not stop.is_set():
            time.sleep(0.05)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = s.recv(65536)
        if not data:
            results["errors"].append(f"holder{n}: empty response after restart"); results["reset"] += 1
    except ConnectionResetError as e:
        results["reset"] += 1; results["errors"].append(f"holder{n}: RESET {e}")
    except OSError as e:
        results["reset"] += 1; results["errors"].append(f"holder{n}: {type(e).__name__} {e}")
    finally:
        s.close()

def hammer(duration):
    """Continuously attempt new connections; count refusals during the transition."""
    end = time.time() + duration
    while time.time() < end:
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=2)
            s.close(); results["opened"] += 1
        except ConnectionRefusedError:
            results["refused"] += 1
        except OSError as e:
            results["errors"].append(f"hammer: {type(e).__name__} {e}")
        time.sleep(0.005)

with open(CFG, "w") as f:
    f.write(f":{PORT} {{\n\trespond \"ok\" 200\n}}\n")

srv = subprocess.Popen([BIN, "run", "--config", CFG, "--adapter", "caddyfile"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3)
try:
    holders = [threading.Thread(target=holder, args=(i,), daemon=True) for i in range(5)]
    for h in holders: h.start()
    time.sleep(1)
    hammerer = threading.Thread(target=hammer, args=(8,), daemon=True)
    hammerer.start()
    time.sleep(1)
    print(f"  pre-restart opens: {results['opened']}", flush=True)
    srv.send_signal(signal.SIGUSR2)
    print("  SIGUSR2 sent", flush=True)
    hammerer.join(timeout=15)
    stop.set()
    for h in holders: h.join(timeout=5)
finally:
    srv.terminate()
    try: srv.wait(timeout=10)
    except subprocess.TimeoutExpired: srv.kill()

print(json.dumps(results, indent=2))
