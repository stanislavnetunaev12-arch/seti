import argparse
import socket
import struct
import time


NTP_EPOCH = 2208988800
PACKET_SIZE = 48


def system_to_ntp_timestamp(value):
    seconds = int(value) + NTP_EPOCH
    fraction = int((value - int(value)) * (1 << 32)) & 0xFFFFFFFF
    return (seconds << 32) | fraction


def ntp_to_system_timestamp(value):
    seconds = (value >> 32) - NTP_EPOCH
    fraction = (value & 0xFFFFFFFF) / (1 << 32)
    return seconds + fraction


def build_request():
    packet = bytearray(PACKET_SIZE)
    packet[0] = (4 << 3) | 3
    packet[2] = 4
    packet[3] = 250
    struct.pack_into("!Q", packet, 40, system_to_ntp_timestamp(time.time()))
    return packet


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("-p", "--port", type=int, default=123)
    parser.add_argument("-t", "--timeout", type=float, default=3.0)
    return parser.parse_args()


def main():
    args = parse_args()
    request = build_request()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        client_socket.settimeout(args.timeout)
        client_socket.sendto(request, (args.host, args.port))
        response, address = client_socket.recvfrom(512)
    transmit_timestamp = struct.unpack("!Q", response[40:48])[0]
    server_time = ntp_to_system_timestamp(transmit_timestamp)
    local_time = time.time()
    print(f"response from {address[0]}:{address[1]}")
    print(f"packet size: {len(response)}")
    print(f"mode: {response[0] & 0b111}")
    print(f"version: {(response[0] >> 3) & 0b111}")
    print(f"stratum: {response[1]}")
    print(f"server time shift: {server_time - local_time:.6f}")


if __name__ == "__main__":
    main()
