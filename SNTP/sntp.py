import argparse
import concurrent.futures
import socket
import struct
import sys
import time


NTP_EPOCH = 2208988800
PACKET_SIZE = 48


def system_to_ntp_timestamp(value):
    seconds = int(value) + NTP_EPOCH
    fraction = int((value - int(value)) * (1 << 32)) & 0xFFFFFFFF
    return (seconds << 32) | fraction


def ntp_timestamp_to_bytes(value):
    return struct.pack("!Q", value & 0xFFFFFFFFFFFFFFFF)


def build_response(request, receive_time, transmit_time):
    version = (request[0] >> 3) & 0b111
    if version == 0:
        version = 4
    precision = -20
    li = 0
    mode = 4
    first_byte = (li << 6) | (version << 3) | mode
    stratum = 2
    root_delay = 0
    root_dispersion = 0
    reference_id = b"LOCL"
    reference_time = system_to_ntp_timestamp(transmit_time - 1)
    originate_time = struct.unpack("!Q", request[40:48])[0]
    receive_timestamp = system_to_ntp_timestamp(receive_time)
    transmit_timestamp = system_to_ntp_timestamp(transmit_time)
    return b"".join(
        [
            struct.pack("!BBBb", first_byte, stratum, request[2], precision),
            struct.pack("!I", root_delay),
            struct.pack("!I", root_dispersion),
            reference_id,
            ntp_timestamp_to_bytes(reference_time),
            ntp_timestamp_to_bytes(originate_time),
            ntp_timestamp_to_bytes(receive_timestamp),
            ntp_timestamp_to_bytes(transmit_timestamp),
        ]
    )


def handle_request(server_socket, data, address, delay):
    if len(data) < PACKET_SIZE:
        return
    print(address[0], flush=True)
    receive_time = time.time() + delay
    response = build_response(data[:PACKET_SIZE], receive_time, time.time() + delay)
    server_socket.sendto(response, address)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--delay", type=int, default=0)
    parser.add_argument("-p", "--port", type=int, default=123)
    return parser.parse_args()


def main():
    args = parse_args()
    workers = max(4, (os_cpu_count() or 1) * 4)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind(("", args.port))
        print(f"SNTP server started on port {args.port} with delay {args.delay}", flush=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            while True:
                try:
                    data, address = server_socket.recvfrom(1024)
                except KeyboardInterrupt:
                    print("SNTP server stopped", flush=True)
                    return
                executor.submit(handle_request, server_socket, data, address, args.delay)


def os_cpu_count():
    try:
        import os

        return os.cpu_count()
    except Exception:
        return 1


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
