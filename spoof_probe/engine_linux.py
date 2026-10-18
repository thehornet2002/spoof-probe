import os
import socket
import struct
import time
from typing import Callable, Optional, Tuple


class LinuxEngine:
    """Linux engine using kernel raw sockets."""

    def __init__(self):
        if os.geteuid() != 0:
            raise PermissionError("Linux raw sockets require root privileges (run with sudo)")

    def create_sender(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return s

    def send_packet(self, sock: socket.socket, raw_ip_pkt: bytes, dst_ip: str):
        sock.sendto(raw_ip_pkt, (dst_ip, 0))

    def listen_packets(
        self,
        protocols: list,
        filter_port: int,
        timeout: int,
        on_packet: Callable[[str, int, str], None],
        stop_check: Optional[Callable[[], bool]] = None,
    ):
        """
        Listens on raw sockets for specified protocols ('tcp', 'udp', 'icmp').
        """
        proto_map = {
            "tcp": socket.IPPROTO_TCP,
            "udp": socket.IPPROTO_UDP,
            "icmp": socket.IPPROTO_ICMP,
        }

        sockets = []
        for p in protocols:
            if p in proto_map:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto_map[p])
                s.settimeout(0.5)
                sockets.append((p, proto_map[p], s))

        try:
            deadline = time.time() + timeout
            while time.time() < deadline:
                if stop_check and stop_check():
                    break

                for proto_name, proto_num, sock in sockets:
                    try:
                        data, addr = sock.recvfrom(65535)
                        if len(data) < 20:
                            continue

                        # Parse IP Header
                        ihl = (data[0] & 0x0F) * 4
                        if len(data) < ihl:
                            continue

                        src_ip = socket.inet_ntoa(data[12:16])
                        proto_in_pkt = data[9]
                        if proto_in_pkt != proto_num:
                            continue

                        payload = data[ihl:]
                        dst_port = 0
                        if proto_name in ("tcp", "udp") and len(payload) >= 4:
                            dst_port = struct.unpack("!H", payload[2:4])[0]
                            if filter_port > 0 and dst_port != filter_port:
                                continue

                        on_packet(src_ip, dst_port, proto_name)
                    except (socket.timeout, BlockingIOError):
                        continue
                    except Exception:
                        continue
        finally:
            for _, _, s in sockets:
                s.close()
