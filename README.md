# Spoof Probe

Cross-platform bidirectional network probe to test IP spoofing and censorship bypass across **TCP**, **UDP**, and **ICMP**.

Designed to run natively on both **Windows** (using Npcap) and **Linux** (using raw kernel sockets) without external third-party dependencies.

---

## Features

- **Multi-Protocol Testing:** Supports `tcp` (SYN), `udp` (datagram), `icmp` (Echo Request), or `all` concurrently.
- **Bidirectional Probe:** Either side can run as **Sender** or **Receiver** using IP lists.
- **Flexible IP Formats:** Supports single IPs (`1.1.1.1`), IP ranges (`10.0.0.1-10.0.0.50`), and CIDR notations (`192.168.1.0/24`).
- **Windows Npcap Integration:** Bypasses Windows `tcpip.sys` raw socket restrictions by injecting Layer 2 Ethernet frames directly via `wpcap.dll`.
- **Automated CI/CD:** GitHub Actions workflow builds standalone executables for both Linux and Windows.

---

## Quick Start (with Python)

### 1. Setup Environment
```bash
python -m venv .venv

# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1

# On Linux:
source .venv/bin/activate
```

---

## Usage

### Scenario A: Test Inbound from Windows (Iran) to Linux (Server)

#### 1. On Server (Linux Receiver):
```bash
sudo python3 main.py recv --protocol all --port 8090 --src-list ips.txt --timeout 120
```

#### 2. On Client (Windows Sender - Run PowerShell as Administrator):
```powershell
python main.py send --dst-ip <SERVER_IP> --dst-port 8090 --protocol all --src-list ips.txt --count 2
```

Results and passing IPs are saved to `passed_ips.txt` and `passed_ips.json`.

---

### Scenario B: Test Outbound from Linux (Server) to Windows (Iran)

#### 1. On Client (Windows Receiver - Run PowerShell as Administrator):
```powershell
python main.py recv --protocol all --port 5001 --src-list ips.txt --timeout 120
```

#### 2. On Server (Linux Sender):
```bash
sudo python3 main.py send --dst-ip <CLIENT_IP> --dst-port 5001 --protocol all --src-list ips.txt --count 2
```

---

## Standalone Binary Build

You can compile a standalone `.exe` / ELF binary with PyInstaller:

```bash
pip install pyinstaller
pyinstaller --onefile --name spoof-probe main.py
```

Prebuilt binaries are also generated automatically by GitHub Actions on git push tags (`v*`).
