import ipaddress
from typing import Generator, List, Set, Tuple


class IPRangeSet:
    """Compact and fast IP range matcher and iterator."""

    def __init__(self):
        self.ranges: List[Tuple[int, int]] = []
        self._total: int = 0

    def add_range(self, start_int: int, end_int: int):
        if end_int < start_int:
            start_int, end_int = end_int, start_int
        self.ranges.append((start_int, end_int))
        self._total += (end_int - start_int + 1)

    def optimize(self):
        """Merge overlapping or adjacent ranges."""
        if not self.ranges:
            return
        self.ranges.sort(key=lambda r: r[0])
        merged = [self.ranges[0]]
        for cur in self.ranges[1:]:
            prev_start, prev_end = merged[-1]
            if cur[0] <= prev_end + 1:
                merged[-1] = (prev_start, max(prev_end, cur[1]))
            else:
                merged.append(cur)
        self.ranges = merged
        self._total = sum(end - start + 1 for start, end in self.ranges)

    @property
    def total(self) -> int:
        return self._total

    def contains(self, ip_int: int) -> bool:
        # Binary search over sorted ranges
        low = 0
        high = len(self.ranges) - 1
        while low <= high:
            mid = (low + high) // 2
            start, end = self.ranges[mid]
            if start <= ip_int <= end:
                return True
            elif ip_int < start:
                high = mid - 1
            else:
                low = mid + 1
        return False

    def iterate_ips(self) -> Generator[str, None, None]:
        for start, end in self.ranges:
            for ip_val in range(start, end + 1):
                yield str(ipaddress.IPv4Address(ip_val))


def parse_ip_file(file_path: str) -> IPRangeSet:
    """Parses a file containing single IPs, ranges (ip1-ip2), or CIDRs (ip/mask)."""
    ranges = IPRangeSet()
    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            try:
                if "-" in line:
                    parts = line.split("-", 1)
                    ip1 = int(ipaddress.IPv4Address(parts[0].strip()))
                    ip2 = int(ipaddress.IPv4Address(parts[1].strip()))
                    ranges.add_range(ip1, ip2)
                elif "/" in line:
                    net = ipaddress.IPv4Network(line, strict=False)
                    ranges.add_range(int(net.network_address), int(net.broadcast_address))
                else:
                    ip = int(ipaddress.IPv4Address(line))
                    ranges.add_range(ip, ip)
            except Exception as e:
                raise ValueError(f"Line {line_num} ({line}): {e}")

    ranges.optimize()
    return ranges
