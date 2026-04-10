import argparse
import concurrent.futures
import socket
import struct
import sys
import time
import os

NTP_EPOCH = 2208988800
PACKET_SIZE = 48

def system_to_ntp_timestamp(value):
    seconds = int(value) + NTP_EPOCH
    fraction = int((value - int(value)) * (1 << 32)) & 0xFFFFFFFF
    return (seconds << 32) | fraction

def ntp_timestamp_to_bytes(value):
    return struct.pack("!Q", value & 0xFFFFFFFFFFFFFFFF)

def get_real_ntp_time():
    ntp_server = "pool.ntp.org"
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = b'\x1b' + 47 * b'\0'
    try:
        client.settimeout(2.0)
        client.sendto(data, (ntp_server, 123))
        data, address = client.recvfrom(1024)
        unpacked = struct.unpack("!12I", data)[10]
        return unpacked - NTP_EPOCH
    except Exception:
        return time.time()

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
    print(f"Request from: {address[0]}", flush=True)
    real_base_time = get_real_ntp_time()
    receive_time = real_base_time + delay
    response = build_response(data[:PACKET_SIZE], receive_time, real_base_time + delay)
    server_socket.sendto(response, address)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--delay", type=int, default=0)
    parser.add_argument("-p", "--port", type=int, default=123)
    return parser.parse_args()

def main():
    args = parse_args()
    workers = max(4, (os.cpu_count() or 1) * 4)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        try:
            server_socket.bind(("", args.port))
        except PermissionError:
            print(f"Error: Port {args.port} requires root privileges.")
            return
        
        print(f"SNTP Proxy Server started on port {args.port} with delay {args.delay}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            while True:
                try:
                    data, address = server_socket.recvfrom(1024)
                    executor.submit(handle_request, server_socket, data, address, args.delay)
                except KeyboardInterrupt:
                    print("\nServer stopped.")
                    break

if __name__ == "__main__":
    main()
