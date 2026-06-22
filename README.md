# cnp-relay — DPDK 中继数据平面 + 端侧网关 (CNP 实验)

一个用于验证 **out-of-band CNP（Congestion Notification Packet）拥塞抑制** 的实验系统：
DPDK 中继在线抓流、识别大流（heavy hitter），对大流的发送端注入 CNP 包，
触发已 patch 的 msquic 的 BBR 增窗抑制（`CnpSuppressUntil`）。

```
 客户端主机 (Mac)                          中继 VM (ens192)                服务端主机 (10.29.75.103)
 msquic client                          10.103.238.111:4433              msquic server 127.0.0.1:4444
   │ target 127.0.0.1:5000                  DPDK relay                        ▲
   ▼                                     ┌──────────────┐                     │
 shim --role client ─[TUNL|QUIC]──────► │ 抓流/Top-K    │ ─[TUNL|QUIC]──────► shim --role server
   ▲                                     │ 大流→注入CNP  │                     │
   └──────[TUNL|CNP]── 回送 client-shim ◄┤              │ ◄──[TUNL|QUIC]──────┘
          shim 拆头→投本地 msquic         └──────────────┘
          → 触发 BBR 抑制
```

- **shim**：端侧网关，可移植 POSIX UDP 代理（Mac/Linux 通用），与端侧同机。**msquic 不需改动数据平面**，只需带已有的 CNP 接收 patch。
- **relay**：DPDK 单网卡转发 + 检测 + CNP 注入，跑在中继 VM 的 ens192 上。
- **CNP 走隧道回送**给 client-shim 本地投递，**不伪造任何源 IP**，对 vSwitch 设置零依赖。

## 目录

```
include/tunnel_protocol.h   共享：TUNL 隧道头 + msquic "CNP1" 线格式 + flow_id + 内层 QUIC DestCID 解析
shim/shim.c                 端侧网关（POSIX，client/server 双模式）
shim/Makefile               cc -O2 -I../include -o shim shim.c
shim/test_loopback.py       本地回环端到端自测（不需 DPDK）
relay/relay.c               DPDK 中继
relay/meson.build           pkg-config libdpdk
scripts/setup_relay.sh      hugepages + vfio-pci + 绑定 ens192
scripts/run_relay.sh        启动中继
```

## 1. 中继 VM（10.103.238.110，数据网卡 ens192=10.103.238.111）

```bash
# 编译
cd ~/cnp-relay/relay
PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig PATH=$HOME/.local/bin:$PATH \
  meson setup build . && ninja -C build

# 一次性环境配置（会把 ens192 从内核摘下交给 DPDK；SSH 务必走 ens160）
sudo ~/cnp-relay/scripts/setup_relay.sh

# 启动（lcore 0-1，仅放行数据网卡 PCI 0000:0b:00.0）
THRESHOLD_MBPS=10 ~/cnp-relay/scripts/run_relay.sh
```

中继日志：`port up` / `flows=.. big=..` / `CNP -> flow 0x...`。

可调参数（`run_relay.sh` 环境变量）：`RELAY_IP`、`RELAY_PORT`(默认 4433)、`THRESHOLD_MBPS`(单流大流阈值)。

## 2. 服务端主机（10.29.75.103，跑 patched msquic）

```bash
# 编译 shim（无外部依赖）
cd cnp-relay/shim && make

# 起 msquic 服务端（BBR，监听本地 4444）
./artifacts/bin/.../secnetperf -cc:bbr -port:4444 &

# 起 server shim：收中继(10.29.75.103:4433) ↔ 本地 msquic(127.0.0.1:4444)
./shim --role server --bind 10.29.75.103:4433 \
       --msquic 127.0.0.1:4444 --relay 10.103.238.111:4433 -v
```

## 3. 客户端主机（Mac，跑 patched msquic）

```bash
cd cnp-relay/shim && make

# 起 client shim：本地 msquic(127.0.0.1:5000) ↔ 中继(10.103.238.111:4433)，目的=server-shim
./shim --role client --listen 127.0.0.1:5000 \
       --relay 10.103.238.111:4433 --peer 10.29.75.103:4433 -v &

# msquic 客户端做上传测试，target 指向本地 shim
./artifacts/bin/.../secnetperf -target:127.0.0.1 -port:5000 -up:30s -cc:bbr -ptput:1
```

## 4. 期望与判读

- 中继日志出现 `big>=1` 和 `CNP -> flow 0x...`。
- 客户端 msquic 若以 `-DQUIC_CNP_DEBUG` 编译，可见 `[CNP] applied` 与每 RTT
  `[BBR] ... cnpActive=1`；上传吞吐在抑制窗口内出现平台/下降。
- 对照组：不经中继（直连）或 `THRESHOLD_MBPS` 调到极高（不触发），吞吐无抑制。

## 端口/地址约定（默认，可改）

| 角色 | 地址 |
|---|---|
| 中继隧道监听 | `10.103.238.111:4433` |
| client shim 本地（msquic target） | `127.0.0.1:5000` |
| server shim 面向中继 | `10.29.75.103:4433` |
| msquic 服务端 | `127.0.0.1:4444` |

## 本地自测（开发用，不需真实网络/DPDK）

```bash
cd shim && python3 test_loopback.py    # 期望 RESULT: PASS
```
用 Python 软件中继 + 假 msquic 回显，驱动两个真实 shim 进程，验证封装/拆封与 CNP 投递。
