import socket
import struct
import sys
import re
import os
import time

ICMP_ECHO_REQUEST = 8
ICMP_CODE = socket.getprotobyname('icmp')

def checksum(source_string):
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2
    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def create_packet(id):
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = struct.pack('d', time.time())
    my_checksum = checksum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), id, 1)
    return header + data

def get_whois_data(ip):
    if any(re.match(p, ip) for p in [r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', r'^192\.168\.', r'^127\.']):
        return "local"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect(("whois.ripe.net", 43))
            s.send(f"{ip}\r\n".encode())
            resp = ""
            while True:
                d = s.recv(4096)
                if not d: break
                resp += d.decode(errors='ignore')

            netname = re.search(r'netname:\s*(.*)', resp, re.I)
            as_num = re.search(r'origin:\s*(?:AS)?(\d+)', resp, re.I)
            country = re.search(r'country:\s*([A-Z]{2})', resp, re.I)

            out = []
            if netname: out.append(netname.group(1).strip())
            if as_num: out.append(f"AS{as_num.group(1).strip()}")
            if country: out.append(country.group(1).strip())
            return ", ".join(out)
    except: return ""

def start_trace(target):
    try:
        dest_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Ошибка: {target} недоступен или неверен.")
        return

    print(f"Трассировка до {target} [{dest_ip}], макс. 30 прыжков:\n")

    try:
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
        icmp_socket.settimeout(2.0)

        local_ip = socket.gethostbyname(socket.gethostname())
        icmp_socket.bind((local_ip, 0))
        if os.name == 'nt':
            icmp_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    except PermissionError:
        print("sudo")
        return

    my_id = os.getpid() & 0xFFFF

    for ttl in range(1, 31):
        icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        packet = create_packet(my_id)
        curr_addr = "*"

        try:
            icmp_socket.sendto(packet, (dest_ip, 1))

            start_t = time.time()
            while True:
                ready_t = time.time() - start_t
                if ready_t > 2.0: break # Таймаут

                recv_packet, addr = icmp_socket.recvfrom(1024)
                curr_addr = addr[0]

                icmp_header = recv_packet[20:28]
                type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)

                if type == 11 or (type == 0 and p_id == my_id):
                    break
        except socket.timeout:
            pass
        except Exception as e:
            print(f"Ошибка отправки: {e}")

        whois_info = get_whois_data(curr_addr) if curr_addr != "*" else ""
        print(f"{ttl}\t{curr_addr}")
        if whois_info:
            print(f" \t[{whois_info}]")
        print("-" * 30)

        if curr_addr == dest_ip:
            print("\nТрассировка завершена.")
            break

    if os.name == 'nt':
        icmp_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    icmp_socket.close()

if __name__ == "__main__":
    start_trace(sys.argv[1])