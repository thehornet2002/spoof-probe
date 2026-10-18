import json
import os
import platform
import socket
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional

from .iplist import IPRangeSet
from .packet import build_icmp_echo, build_tcp_syn, build_udp

IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    from .engine_win import WindowsNpcapEngine
else:
    from .engine_linux import LinuxEngine


class ProbeRunner:
    """Orchestrates bidirectional sending and receiving tests."""

    def __init__(self):
        if IS_WINDOWS:
            self.engine = WindowsNpcapEngine()
        else:
            self.engine = LinuxEngine()

    def run_sender(
        self,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        ranges: IPRangeSet,
        packet_count: int = 2,
        delay_ms: float = 0.5,
    ):
        """Sends spoofed packets across the specified IP ranges."""
        protocols = ["tcp", "udp", "icmp"] if protocol == "all" else [protocol]
        total_ips = ranges.total
        print(f"[*] Starting Sender -> Target: {dst_ip}:{dst_port} | Protocols: {protocols} | Sources: {total_ips} IPs")

        sent_count = 0
        err_count = 0
        start_time = time.time()

        if IS_WINDOWS:
            src_mac, dst_mac, dev_name = self.engine.resolve_interface_and_macs(dst_ip)
            print(f"[*] Npcap Adapter: {dev_name}")
            print(f"[*] Gateway MAC: {dst_mac.hex(':').upper()}")
            handle = self.engine.open_device(dev_name)
        else:
            handle = self.engine.create_sender()

        try:
            for idx, src_ip in enumerate(ranges.iterate_ips(), 1):
                src_port = 1024 + (idx % 60000)

                for p in protocols:
                    for _ in range(packet_count):
                        try:
                            if p == "tcp":
                                raw_pkt = build_tcp_syn(src_ip, dst_ip, src_port, dst_port)
                            elif p == "udp":
                                raw_pkt = build_udp(src_ip, dst_ip, src_port, dst_port, b"SPOOF_PROBE")
                            elif p == "icmp":
                                raw_pkt = build_icmp_echo(src_ip, dst_ip, idx & 0xFFFF, 1)
                            else:
                                continue

                            if IS_WINDOWS:
                                self.engine.send_frame(handle, src_mac, dst_mac, raw_pkt)
                            else:
                                self.engine.send_packet(handle, raw_pkt, dst_ip)

                            sent_count += 1
                        except Exception as e:
                            err_count += 1

                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)

                if idx % 500 == 0 or idx == total_ips:
                    elapsed = time.time() - start_time
                    rate = sent_count / elapsed if elapsed > 0 else 0
                    pct = (idx / total_ips) * 100
                    print(f"[{pct:5.1f}%] Progress: {idx}/{total_ips} IPs | Sent: {sent_count} pkts ({rate:.0f} pps)")

        finally:
            if IS_WINDOWS:
                self.engine.close(handle)
            else:
                handle.close()

        elapsed = time.time() - start_time
        print(f"[✓] Sender finished in {elapsed:.2f}s | Sent: {sent_count} pkts | Errors: {err_count}")

    def run_receiver(
        self,
        filter_port: int,
        protocol: str,
        ranges: IPRangeSet,
        packet_count: int = 2,
        max_loss_pct: float = 50.0,
        timeout: int = 60,
        output_file: Optional[str] = None,
    ):
        """Listens for inbound spoofed packets and compiles pass/fail results."""
        protocols = ["tcp", "udp", "icmp"] if protocol == "all" else [protocol]
        print(f"[*] Starting Receiver -> Listening for protocols: {protocols} | Port: {filter_port}")
        print(f"[*] Expected IP set: {ranges.total} IPs | Timeout: {timeout}s | Max allowed loss: {max_loss_pct}%")

        # Map: IP string -> {proto: count}
        received_map: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

        def on_packet(src_ip: str, dst_port: int, proto_name: str):
            try:
                ip_int = int(socket.inet_aton(src_ip).hex(), 16)
            except Exception:
                return

            if not ranges.contains(ip_int):
                return

            received_map[src_ip][proto_name] += 1
            total_rx = sum(received_map[src_ip].values())
            if total_rx == 1:
                print(f"[+] Received first packet from: {src_ip} ({proto_name.upper()})")

        start_time = time.time()

        if IS_WINDOWS:
            # On Windows, listen on active adapter
            _, _, dev_name = self.engine.resolve_interface_and_macs("8.8.8.8")
            bpf_parts = []
            if "tcp" in protocols:
                bpf_parts.append(f"(tcp and dst port {filter_port})" if filter_port > 0 else "tcp")
            if "udp" in protocols:
                bpf_parts.append(f"(udp and dst port {filter_port})" if filter_port > 0 else "udp")
            if "icmp" in protocols:
                bpf_parts.append("icmp")
            bpf_filter = " or ".join(bpf_parts)
            print(f"[*] Npcap BPF filter: {bpf_filter} on {dev_name}")
            self.engine.listen_packets(dev_name, bpf_filter, timeout, on_packet)
        else:
            self.engine.listen_packets(protocols, filter_port, timeout, on_packet)

        # Tally results
        results = []
        passed_ips = []
        expected_per_ip = packet_count * len(protocols)

        for src_ip, proto_counts in received_map.items():
            total_rx = sum(proto_counts.values())
            loss_pct = max(0.0, ((expected_per_ip - total_rx) / expected_per_ip) * 100.0)
            passed = loss_pct <= max_loss_pct

            res_item = {
                "ip": src_ip,
                "received": total_rx,
                "expected": expected_per_ip,
                "loss_pct": round(loss_pct, 1),
                "breakdown": dict(proto_counts),
                "passed": passed,
            }
            results.append(res_item)
            if passed:
                passed_ips.append(src_ip)

        print("\n" + "═" * 60)
        print(f"[*] Receiver Test Completed:")
        print(f"    Total monitored IPs:  {ranges.total}")
        print(f"    IPs received packets: {len(received_map)}")
        print(f"    IPs passed criteria:  {len(passed_ips)} (Loss <= {max_loss_pct}%)")
        print("═" * 60)

        # Save passed IPs to text file
        out_txt = output_file if output_file else "passed_ips.txt"
        with open(out_txt, "w", encoding="utf-8") as f:
            for ip in sorted(passed_ips):
                f.write(f"{ip}\n")
        print(f"[✓] Saved {len(passed_ips)} passed IPs to: {out_txt}")

        # Save detailed JSON report
        report_json = out_txt.rsplit(".", 1)[0] + ".json"
        with open(report_json, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "total_monitored": ranges.total,
                    "received_count": len(received_map),
                    "passed_count": len(passed_ips),
                    "max_loss_pct": max_loss_pct,
                    "results": results,
                },
                f,
                indent=2,
            )
        print(f"[✓] Saved detailed report to: {report_json}")
