#!/usr/bin/env python3
"""
Local loopback end-to-end test for shim.c — no DPDK required.

Topology (all on 127.0.0.1):

  fake msquic client  --5000-->  client shim  --7000-->  software relay
        ^                                                      |
        |                                                 (forward by dir)
        +--CNP & echoes--                                      v
                                  server shim  <--6001--  (relay)
                                      |
                                  --4444-->  fake msquic server (echo)

The software relay mimics what the DPDK relay must do:
  - dir=0 (c2s): learn the client's outer addr by flow_id, forward to orig_dst
                 (the server shim), keeping the tunnel header.
  - dir=1 (s2c): forward to the learned client outer addr.
  - after a few forward packets it INJECTS a tunnel(type=CNP,dir=1) back toward
    the client, carrying a "CNP1" payload — exercising the CNP delivery path.

Pass criteria: the fake client gets its echoes back AND receives a CNP packet
(0x00 "CNP1" ...) delivered by the client shim.
"""
import socket, struct, subprocess, sys, threading, time, os

HDR = struct.Struct("!IBBBBIHH4s4sHH")  # magic,ver,type,dir,flags,flow_id,plen,resv,sip,dip,sport,dport
TUNNEL_MAGIC = 0x54554E4C
T_DATA, T_CNP = 0, 1
D_C2S, D_S2C = 0, 1

CLIENT_LISTEN = ("127.0.0.1", 5000)
SERVER_BIND   = ("127.0.0.1", 6001)
RELAY         = ("127.0.0.1", 7000)
MSQUIC_SERVER = ("127.0.0.1", 4444)

stop = threading.Event()
got_cnp = threading.Event()


def unpack_hdr(b):
    (magic, ver, typ, d, flags, fid, plen, resv, sip, dip, sport, dport) = HDR.unpack_from(b)
    return dict(magic=magic, ver=ver, type=typ, dir=d, flow_id=fid, plen=plen,
                sip=sip, dip=dip, sport=sport, dport=dport)


def fake_msquic_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(MSQUIC_SERVER)
    s.settimeout(0.5)
    while not stop.is_set():
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        s.sendto(b"ECHO:" + data, addr)   # echo back to whoever (the server shim)
    s.close()


def software_relay():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(RELAY)
    s.settimeout(0.5)
    client_outer = {}     # flow_id -> client shim outer addr
    fwd_count = 0
    while not stop.is_set():
        try:
            pkt, src = s.recvfrom(65535)
        except socket.timeout:
            continue
        if len(pkt) < HDR.size:
            continue
        h = unpack_hdr(pkt)
        if h["magic"] != TUNNEL_MAGIC:
            continue
        if h["dir"] == D_C2S:
            client_outer[h["flow_id"]] = src
            dst = (socket.inet_ntoa(h["dip"]), h["dport"])   # orig_dst = server shim
            s.sendto(pkt, dst)
            fwd_count += 1
            # Inject a CNP toward the client after a few forward packets.
            if fwd_count == 3:
                cid = bytes(range(9))  # 9-byte fake client CID
                cnp = bytes([0x00]) + b"CNP1" + bytes([0]) + struct.pack("<H", 200) + bytes([len(cid)]) + cid
                hdr = HDR.pack(TUNNEL_MAGIC, 1, T_CNP, D_S2C, 0, h["flow_id"],
                               len(cnp), 0, h["dip"], h["sip"], h["dport"], h["sport"])
                s.sendto(hdr + cnp, src)
                print("[relay] injected CNP -> client outer", src)
        elif h["dir"] == D_S2C:
            dst = client_outer.get(h["flow_id"])
            if dst:
                s.sendto(pkt, dst)
    s.close()


def fake_msquic_client():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(0.5)
    echoes = 0
    deadline = time.time() + 6
    for i in range(8):
        s.sendto(f"hello-{i}".encode(), CLIENT_LISTEN)
        time.sleep(0.1)
    while time.time() < deadline:
        try:
            data, _ = s.recvfrom(65535)
        except socket.timeout:
            continue
        if data[:5] == b"\x00CNP1":
            print("[client] *** received CNP:", data.hex())
            got_cnp.set()
        elif data.startswith(b"ECHO:"):
            echoes += 1
    s.close()
    print(f"[client] echoes received: {echoes}")
    return echoes


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    shim = os.path.join(here, "shim")
    if not os.path.exists(shim):
        subprocess.check_call(["make"], cwd=here)

    # background services
    threading.Thread(target=fake_msquic_server, daemon=True).start()
    threading.Thread(target=software_relay, daemon=True).start()
    time.sleep(0.3)

    procs = [
        subprocess.Popen([shim, "--role", "server", "--bind", "127.0.0.1:6001",
                          "--msquic", "127.0.0.1:4444", "--relay", "127.0.0.1:7000", "-v"]),
        subprocess.Popen([shim, "--role", "client", "--listen", "127.0.0.1:5000",
                          "--relay", "127.0.0.1:7000", "--peer", "127.0.0.1:6001", "-v"]),
    ]
    time.sleep(0.4)

    echoes = fake_msquic_client()

    stop.set()
    time.sleep(0.3)
    for p in procs:
        p.terminate()

    ok = echoes >= 6 and got_cnp.is_set()
    print("\nRESULT:", "PASS" if ok else "FAIL",
          f"(echoes={echoes}, cnp={got_cnp.is_set()})")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
