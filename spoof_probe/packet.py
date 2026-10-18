import random
import socket
import struct


def checksum(data: bytes) -> int:
    """Calculates internet checksum (RFC 1071)."""
    if len(data) % 2 == 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    while (s >> 16) > 0:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def build_ip_header(src_ip: str, dst_ip: str, proto: int, payload_len: int, ip_id: int = 0) -> bytes:
    """Constructs 20-byte IPv4 header."""
    version_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + payload_len
    if ip_id == 0:
        ip_id = random.randint(1, 65535)
    flags_fragment = 0x4000  # Don't Fragment
    ttl = 64
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    hdr_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_len,
        ip_id,
        flags_fragment,
        ttl,
        proto,
        0,
        src_bytes,
        dst_bytes,
    )
    csum = checksum(hdr_no_csum)
    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_len,
        ip_id,
        flags_fragment,
        ttl,
        proto,
        csum,
        src_bytes,
        dst_bytes,
    )


def build_tcp_syn(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int = 0) -> bytes:
    """Constructs raw IPv4 + TCP SYN packet."""
    if seq == 0:
        seq = random.randint(1000, 4294967200)

    # 20 bytes TCP Header
    tcp_hdr_no_csum = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        0,       # Ack number
        (5 << 4),# Data offset
        0x02,    # Flags: SYN
        64240,   # Window size
        0,       # Checksum placeholder
        0,       # Urgent pointer
    )

    # Pseudo-header for TCP checksum
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    pseudo = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, 6, len(tcp_hdr_no_csum))
    csum = checksum(pseudo + tcp_hdr_no_csum)

    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        0,
        (5 << 4),
        0x02,
        64240,
        csum,
        0,
    )

    ip_hdr = build_ip_header(src_ip, dst_ip, 6, len(tcp_hdr))
    return ip_hdr + tcp_hdr


def build_udp(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes = b"SPOOF_PROBE") -> bytes:
    """Constructs raw IPv4 + UDP packet."""
    udp_len = 8 + len(payload)
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    udp_no_csum = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload
    pseudo = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, 17, udp_len)
    csum = checksum(pseudo + udp_no_csum)
    if csum == 0:
        csum = 0xFFFF

    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, csum) + payload
    ip_hdr = build_ip_header(src_ip, dst_ip, 17, len(udp_hdr))
    return ip_hdr + udp_hdr


def build_icmp_echo(src_ip: str, dst_ip: str, ident: int = 1, seq: int = 1, payload: bytes = b"PING") -> bytes:
    """Constructs raw IPv4 + ICMP Echo Request packet."""
    icmp_no_csum = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
    csum = checksum(icmp_no_csum)
    icmp_pkt = struct.pack("!BBHHH", 8, 0, csum, ident, seq) + payload

    ip_hdr = build_ip_header(src_ip, dst_ip, 1, len(icmp_pkt))
    return ip_hdr + icmp_pkt
