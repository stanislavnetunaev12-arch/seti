import argparse
import concurrent.futures
import socket
import struct
import sys
from dataclasses import dataclass


TCP_TIMEOUT = 0.7
UDP_TIMEOUT = 1.0
MAX_WORKERS = 100


@dataclass(frozen=True)
class ScanResult:
    transport: str
    port: int
    protocol: str | None = None

    def render(self) -> str:
        if self.protocol:
            return f"{self.transport} {self.port} {self.protocol}"
        return f"{self.transport} {self.port}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("-t", "--tcp", action="store_true")
    parser.add_argument("-u", "--udp", action="store_true")
    parser.add_argument("--start", type=int, required=True)
    parser.add_argument("--count", type=int, required=True)
    return parser


def validate_args(args: argparse.Namespace) -> None:
    if not args.tcp and not args.udp:
        raise ValueError("Нужно указать хотя бы один режим: --tcp или --udp.")
    if args.start < 1 or args.start > 65535:
        raise ValueError("Начальный порт должен быть в диапазоне 1..65535.")
    if args.count < 1:
        raise ValueError("Количество портов должно быть положительным.")
    if args.start + args.count - 1 > 65535:
        raise ValueError("Диапазон портов выходит за пределы 1..65535.")


def resolve_host(host: str) -> str:
    return socket.gethostbyname(host)


def dns_query_payload() -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    labels = b"".join(len(part).to_bytes(1, "big") + part.encode("ascii") for part in ("example", "com"))
    question = labels + b"\x00" + struct.pack("!HH", 1, 1)
    return header + question


def ntp_payload() -> bytes:
    return b"\x1b" + b"\x00" * 47


def http_payload(host: str) -> bytes:
    return f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii", errors="ignore")


def detect_tcp_protocol(sock: socket.socket, host: str) -> str | None:
    try:
        sock.settimeout(TCP_TIMEOUT)
        try:
            banner = sock.recv(1024)
        except socket.timeout:
            banner = b""
        if banner.startswith(b"220"):
            upper = banner.upper()
            if b"SMTP" in upper or b"ESMTP" in upper:
                return "SMTP"
        if banner.startswith(b"+OK"):
            return "POP3"
        if banner.startswith(b"* OK"):
            return "IMAP"
        if banner.startswith((b"HTTP/", b"<!DOCTYPE", b"<html", b"HTTP")):
            return "HTTP"
        probes = (
            ("HTTP", http_payload(host), (b"HTTP/", b"<!DOCTYPE", b"<html")),
            ("SMTP", b"EHLO portscan.local\r\n", (b"250", b"220")),
            ("POP3", b"CAPA\r\n", (b"+OK", b"-ERR")),
            ("IMAP", b"A001 CAPABILITY\r\n", (b"*", b"A001")),
        )
        for protocol, payload, signatures in probes:
            try:
                sock.sendall(payload)
                response = sock.recv(2048)
            except socket.timeout:
                continue
            except OSError:
                continue
            if any(response.startswith(signature) for signature in signatures):
                return protocol
            upper = response.upper()
            if protocol == "HTTP" and b"HTTP/" in upper:
                return protocol
            if protocol == "SMTP" and b"SMTP" in upper:
                return protocol
            if protocol == "POP3" and b"+OK" in upper:
                return protocol
            if protocol == "IMAP" and b"CAPABILITY" in upper:
                return protocol
    except OSError:
        return None
    return None


def scan_tcp_port(host: str, port: int) -> ScanResult | None:
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT) as sock:
            protocol = detect_tcp_protocol(sock, host)
            return ScanResult("TCP", port, protocol)
    except PermissionError:
        return None
    except OSError:
        return None


def is_dns_response(data: bytes) -> bool:
    return len(data) >= 12 and data[:2] == b"\x12\x34"


def is_ntp_response(data: bytes) -> bool:
    if len(data) < 48:
        return False
    mode = data[0] & 0x07
    version = (data[0] >> 3) & 0x07
    return mode in {4, 5} and 1 <= version <= 4


def detect_udp_protocol(host: str, port: int) -> str | None:
    probes = (
        ("DNS", dns_query_payload(), is_dns_response),
        ("NTP", ntp_payload(), is_ntp_response),
        ("HTTP", http_payload(host), lambda data: data.startswith(b"HTTP/")),
    )
    for protocol, payload, matcher in probes:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(UDP_TIMEOUT)
                sock.connect((host, port))
                sock.send(payload)
                data = sock.recv(4096)
                if matcher(data):
                    return protocol
        except PermissionError:
            continue
        except (socket.timeout, ConnectionResetError, OSError):
            continue
    return None


def scan_udp_port(host: str, port: int) -> ScanResult | None:
    protocol = detect_udp_protocol(host, port)
    if protocol is None:
        return None
    return ScanResult("UDP", port, protocol)


def scan_ports(host: str, ports: range, tcp_enabled: bool, udp_enabled: bool) -> list[ScanResult]:
    results: list[ScanResult] = []
    tasks: list[tuple[str, int]] = []
    if tcp_enabled:
        tasks.extend(("TCP", port) for port in ports)
    if udp_enabled:
        tasks.extend(("UDP", port) for port in ports)
    workers = min(MAX_WORKERS, max(1, len(tasks)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map: dict[concurrent.futures.Future[ScanResult | None], tuple[str, int]] = {}
        for transport, port in tasks:
            if transport == "TCP":
                future = executor.submit(scan_tcp_port, host, port)
            else:
                future = executor.submit(scan_udp_port, host, port)
            future_map[future] = (transport, port)
        for future in concurrent.futures.as_completed(future_map):
            result = future.result()
            if result is not None:
                results.append(result)
    results.sort(key=lambda item: (item.transport, item.port))
    return results


def main() -> int:
    parser = build_parser()
    try:
        args = parser.parse_args()
        validate_args(args)
        host = resolve_host(args.host)
        ports = range(args.start, args.start + args.count)
        results = scan_ports(host, ports, args.tcp, args.udp)
        for result in results:
            print(result.render())
        return 0
    except PermissionError:
        print("Недостаточно прав для выполнения сетевого сканирования.", file=sys.stderr)
        return 1
    except socket.gaierror:
        print("Не удалось разрешить имя хоста.", file=sys.stderr)
        return 1
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Сканирование остановлено пользователем.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
