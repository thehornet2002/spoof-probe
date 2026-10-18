import ctypes
import os
import socket
import struct
import sys
import time
from ctypes import byref, c_char_p, c_int, c_uint, c_void_p, create_string_buffer, POINTER, Structure
from typing import Callable, Optional, Tuple


class MIB_IPFORWARDROW(Structure):
    _fields_ = [
        ("ForwardDest", c_uint),
        ("ForwardMask", c_uint),
        ("ForwardPolicy", c_uint),
        ("ForwardNextHop", c_uint),
        ("ForwardIfIndex", c_uint),
        ("ForwardType", c_uint),
        ("ForwardProto", c_uint),
        ("ForwardAge", c_uint),
        ("ForwardNextHopAS", c_uint),
        ("ForwardMetric1", c_uint),
        ("ForwardMetric2", c_uint),
        ("ForwardMetric3", c_uint),
        ("ForwardMetric4", c_uint),
        ("ForwardMetric5", c_uint),
    ]


class IP_ADAPTER_INFO(Structure):
    pass


IP_ADAPTER_INFO._fields_ = [
    ("Next", POINTER(IP_ADAPTER_INFO)),
    ("ComboIndex", c_uint),
    ("AdapterName", ctypes.c_char * 260),
    ("Description", ctypes.c_char * 132),
    ("AddressLength", c_uint),
    ("Address", ctypes.c_ubyte * 8),
    ("Index", c_uint),
    ("Type", c_uint),
    ("DhcpEnabled", c_uint),
    ("CurrentIpAddress", c_void_p),
    ("IpAddressList", ctypes.c_char * 32),
    ("GatewayList", ctypes.c_char * 32),
    ("DhcpServer", ctypes.c_char * 32),
    ("HaveWins", c_int),
    ("PrimaryWinsServer", ctypes.c_char * 32),
    ("SecondaryWinsServer", ctypes.c_char * 32),
    ("LeaseObtained", ctypes.c_int64),
    ("LeaseExpires", ctypes.c_int64),
]


class bpf_program(Structure):
    _fields_ = [
        ("bf_len", c_uint),
        ("bf_insns", c_void_p),
    ]


class pcap_pkthdr(Structure):
    _fields_ = [
        ("ts_sec", ctypes.c_long),
        ("ts_usec", ctypes.c_long),
        ("caplen", c_uint),
        ("len", c_uint),
    ]


class WindowsNpcapEngine:
    """Windows engine using Npcap (wpcap.dll) via ctypes."""

    def __init__(self):
        # Admin check
        shell32 = ctypes.windll.shell32
        if not shell32.IsUserAnAdmin():
            raise PermissionError("Windows Npcap requires Administrator privileges (run PowerShell as Administrator)")

        # Load wpcap.dll
        self.wpcap = None
        candidates = [
            r"C:\Windows\System32\Npcap\wpcap.dll",
            "wpcap.dll",
        ]
        for c in candidates:
            try:
                self.wpcap = ctypes.cdll.LoadLibrary(c)
                break
            except Exception:
                continue

        if not self.wpcap:
            raise RuntimeError("Npcap is not installed or wpcap.dll not found. Please install Npcap from https://npcap.com")

        # Explicit 64-bit prototype declarations to prevent pointer truncation & access violations
        self.wpcap.pcap_open_live.restype = c_void_p
        self.wpcap.pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]

        self.wpcap.pcap_close.restype = None
        self.wpcap.pcap_close.argtypes = [c_void_p]

        self.wpcap.pcap_sendpacket.restype = c_int
        self.wpcap.pcap_sendpacket.argtypes = [c_void_p, c_char_p, c_int]

        self.wpcap.pcap_next_ex.restype = c_int
        self.wpcap.pcap_next_ex.argtypes = [c_void_p, POINTER(POINTER(pcap_pkthdr)), POINTER(c_void_p)]

        self.wpcap.pcap_compile.restype = c_int
        self.wpcap.pcap_compile.argtypes = [c_void_p, POINTER(bpf_program), c_char_p, c_int, c_uint]

        self.wpcap.pcap_setfilter.restype = c_int
        self.wpcap.pcap_setfilter.argtypes = [c_void_p, POINTER(bpf_program)]

        self.wpcap.pcap_freecode.restype = None
        self.wpcap.pcap_freecode.argtypes = [POINTER(bpf_program)]

        self.wpcap.pcap_geterr.restype = c_char_p
        self.wpcap.pcap_geterr.argtypes = [c_void_p]

        self.iphlpapi = ctypes.windll.iphlpapi
        self.iphlpapi.GetBestRoute.restype = c_uint
        self.iphlpapi.GetBestRoute.argtypes = [c_uint, c_uint, POINTER(MIB_IPFORWARDROW)]

        self.iphlpapi.SendARP.restype = c_uint
        self.iphlpapi.SendARP.argtypes = [c_uint, c_uint, c_void_p, POINTER(c_uint)]

        self.iphlpapi.GetAdaptersInfo.restype = c_uint
        self.iphlpapi.GetAdaptersInfo.argtypes = [c_void_p, POINTER(c_uint)]

    def resolve_interface_and_macs(self, dst_ip: str) -> Tuple[bytes, bytes, str]:
        """Resolves (src_mac, dst_gateway_mac, dev_name) for destination IP."""
        dst_bytes = socket.inet_aton(dst_ip)
        dst_val = struct.unpack("<I", dst_bytes)[0]

        row = MIB_IPFORWARDROW()
        res = self.iphlpapi.GetBestRoute(dst_val, 0, byref(row))
        if res != 0:
            raise RuntimeError(f"GetBestRoute failed for {dst_ip}: {res}")

        gw_val = row.ForwardNextHop if row.ForwardNextHop != 0 else dst_val

        # ARP gateway MAC
        mac_buf = (ctypes.c_ubyte * 6)()
        mac_len = c_uint(6)
        res_arp = self.iphlpapi.SendARP(gw_val, 0, byref(mac_buf), byref(mac_len))
        if res_arp == 0 and mac_len.value == 6:
            dst_mac = bytes(mac_buf)
        else:
            dst_mac = b"\xff\xff\xff\xff\xff\xff"

        # Resolve Adapter Name and Local MAC
        src_mac = b"\x00\x00\x00\x00\x00\x00"
        dev_name = ""

        buf_size = c_uint(0)
        self.iphlpapi.GetAdaptersInfo(None, byref(buf_size))
        if buf_size.value > 0:
            info_buf = (ctypes.c_ubyte * buf_size.value)()
            if self.iphlpapi.GetAdaptersInfo(byref(info_buf), byref(buf_size)) == 0:
                p_info = ctypes.cast(byref(info_buf), POINTER(IP_ADAPTER_INFO))
                while p_info:
                    info = p_info.contents
                    if info.Index == row.ForwardIfIndex:
                        src_mac = bytes(info.Address[:6])
                        adapter_name = info.AdapterName.decode("ascii", "ignore").strip("\x00")
                        dev_name = f"\\Device\\NPF_{adapter_name}"
                        break
                    p_info = info.Next

        if not dev_name:
            raise RuntimeError(f"Could not find Npcap device for interface index {row.ForwardIfIndex}")

        return src_mac, dst_mac, dev_name

    def open_device(self, dev_name: str, snaplen: int = 65536, promisc: int = 1, timeout_ms: int = 50) -> c_void_p:
        errbuf = create_string_buffer(256)
        c_dev = dev_name.encode("ascii")
        handle = self.wpcap.pcap_open_live(c_dev, snaplen, promisc, timeout_ms, errbuf)
        if not handle:
            raise RuntimeError(f"pcap_open_live failed on {dev_name}: {errbuf.value.decode('ascii', 'ignore')}")
        return handle

    def set_filter(self, handle: c_void_p, filter_str: str):
        bpf = bpf_program()
        c_filter = filter_str.encode("ascii")
        rc = self.wpcap.pcap_compile(handle, byref(bpf), c_filter, 1, 0)
        if rc == 0:
            self.wpcap.pcap_setfilter(handle, byref(bpf))
            self.wpcap.pcap_freecode(byref(bpf))

    def send_frame(self, handle: c_void_p, src_mac: bytes, dst_mac: bytes, ip_packet: bytes):
        """Prepends Ethernet header and transmits via pcap_sendpacket."""
        if not handle:
            raise RuntimeError("Cannot send frame: pcap handle is null")
        eth_hdr = dst_mac + src_mac + b"\x08\x00"  # EtherType IPv4
        frame = eth_hdr + ip_packet
        res = self.wpcap.pcap_sendpacket(handle, frame, len(frame))
        if res != 0:
            err = self.wpcap.pcap_geterr(handle)
            err_msg = err.decode("ascii", "ignore") if err else "unknown"
            raise RuntimeError(f"pcap_sendpacket failed: {err_msg}")

    def close(self, handle: c_void_p):
        if handle:
            self.wpcap.pcap_close(handle)

    def listen_packets(
        self,
        dev_name: str,
        filter_str: str,
        timeout: int,
        on_packet: Callable[[str, int, str], None],
        stop_check: Optional[Callable[[], bool]] = None,
    ):
        """Listens on Npcap device and extracts packet information."""
        handle = self.open_device(dev_name, timeout_ms=50)
        if filter_str:
            self.set_filter(handle, filter_str)

        try:
            deadline = time.time() + timeout
            hdr_ptr = POINTER(pcap_pkthdr)()
            data_ptr = c_void_p()

            while time.time() < deadline:
                if stop_check and stop_check():
                    break

                res = self.wpcap.pcap_next_ex(handle, byref(hdr_ptr), byref(data_ptr))
                if res == 0:
                    time.sleep(0.001)
                    continue
                if res < 0:
                    break

                caplen = hdr_ptr.contents.caplen
                raw_bytes = (ctypes.c_ubyte * caplen).from_address(data_ptr.value)
                data = bytes(raw_bytes)

                if len(data) < 34:  # 14 eth + 20 ip
                    continue

                # Check EtherType IPv4
                if data[12:14] != b"\x08\x00":
                    continue

                ip_data = data[14:]
                ihl = (ip_data[0] & 0x0F) * 4
                if len(ip_data) < ihl:
                    continue

                proto_num = ip_data[9]
                src_ip = socket.inet_ntoa(ip_data[12:16])
                payload = ip_data[ihl:]

                proto_name = "unknown"
                dst_port = 0

                if proto_num == 6:
                    proto_name = "tcp"
                    if len(payload) >= 4:
                        dst_port = struct.unpack("!H", payload[2:4])[0]
                elif proto_num == 17:
                    proto_name = "udp"
                    if len(payload) >= 4:
                        dst_port = struct.unpack("!H", payload[2:4])[0]
                elif proto_num == 1:
                    proto_name = "icmp"

                on_packet(src_ip, dst_port, proto_name)

        finally:
            self.close(handle)
