import argparse
import sys

from .iplist import parse_ip_file
from .runner import ProbeRunner


def main():
    parser = argparse.ArgumentParser(
        prog="spoof-probe",
        description="Cross-platform Bidirectional Spoofed IP & Protocol Probe (TCP, UDP, ICMP)",
    )

    subparsers = parser.add_subparsers(dest="mode", required=True, help="Operating mode: sender or receiver")

    # Sender subcommand
    p_send = subparsers.add_parser("send", help="Send spoofed packets to a remote target")
    p_send.add_argument("--dst-ip", required=True, help="Destination IP of remote node")
    p_send.add_argument("--dst-port", type=int, default=8090, help="Destination port for TCP/UDP (default: 8090)")
    p_send.add_argument("--src-list", required=True, help="File containing source IPs (single, range, CIDR)")
    p_send.add_argument(
        "--protocol",
        choices=["all", "tcp", "udp", "icmp"],
        default="all",
        help="Protocol to test (default: all)",
    )
    p_send.add_argument("--count", type=int, default=2, help="Packets per IP per protocol (default: 2)")
    p_send.add_argument("--delay-ms", type=float, default=0.2, help="Delay between IPs in ms (default: 0.2)")

    # Receiver subcommand
    p_recv = subparsers.add_parser("recv", help="Listen for inbound spoofed packets and record passing IPs")
    p_recv.add_argument("--port", type=int, default=8090, help="Listen / filter port for TCP/UDP (default: 8090)")
    p_recv.add_argument("--src-list", required=True, help="File containing expected source IPs")
    p_recv.add_argument(
        "--protocol",
        choices=["all", "tcp", "udp", "icmp"],
        default="all",
        help="Protocol to listen for (default: all)",
    )
    p_recv.add_argument("--count", type=int, default=2, help="Expected packets per IP per protocol (default: 2)")
    p_recv.add_argument("--max-loss", type=float, default=50.0, help="Max packet loss percentage to pass (default: 50.0)")
    p_recv.add_argument("--timeout", type=int, default=90, help="Listening timeout in seconds (default: 90)")
    p_recv.add_argument("-o", "--output", default="passed_ips.txt", help="Output file for passed IPs")

    args = parser.parse_args()

    print(f"[*] Parsing IP ranges from {args.src_list} ...")
    ranges = parse_ip_file(args.src_list)
    print(f"[*] Loaded {ranges.total} total source IPs from {args.src_list}")

    runner = ProbeRunner()

    if args.mode == "send":
        runner.run_sender(
            dst_ip=args.dst_ip,
            dst_port=args.dst_port,
            protocol=args.protocol,
            ranges=ranges,
            packet_count=args.count,
            delay_ms=args.delay_ms,
        )
    elif args.mode == "recv":
        runner.run_receiver(
            filter_port=args.port,
            protocol=args.protocol,
            ranges=ranges,
            packet_count=args.count,
            max_loss_pct=args.max_loss,
            timeout=args.timeout,
            output_file=args.output,
        )


if __name__ == "__main__":
    main()
