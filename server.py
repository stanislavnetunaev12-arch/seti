import socket
import struct
import sys
import re
import os
import time

def get_whois_data(ip):
    local_patterns = [r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', r'^192\.168\.', r'^127\.']
    if any(re.match(p, ip) for p in local_patterns):
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
            if as_num: out.append(as_num.group(1).strip())
            if country: out.append(country.group(1).strip())
            return ", ".join(out)
    except:
        return ""

def checksum(data):
    if len(data) % 2: data += b'\x00'
    res = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16
    return socket.htons(~res & 0xffff)

def start_trace(target):
    try:
        dest_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{target} is invalid") # Ошибка по ТЗ [cite: 22]
        return

    try:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_socket.settimeout(2.0)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        recv_socket.bind((local_ip, 0))
        if os.name == 'nt':
            recv_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except PermissionError:
        print("Запустите терминал от имени Администратора.") 
        return

    my_id = os.getpid() & 0xFFFF

    for ttl in range(1, 31):
        header = struct.pack("bbHHh", 8, 0, 0, my_id, 1)
        data = b"ping"
        my_cksum = checksum(header + data)
        packet = struct.pack("bbHHh", 8, 0, my_cksum, my_id, 1) + data

        curr_addr = "*"
        recv_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        try:
            recv_socket.sendto(packet, (dest_ip, 1))
            start_time = time.time()
            while time.time() - start_time < 2.0:
                pkt, addr = recv_socket.recvfrom(1024)
                icmp_type = pkt[20]
                if icmp_type == 11 or icmp_type == 0:
                    curr_addr = addr[0]
                    break
        except socket.timeout:
            pass

        if curr_addr == "*":
            print(f"{ttl}. *")
        else:
            print(f"{ttl}. {curr_addr}")
            info = get_whois_data(curr_addr)
            if info:
                print(info)

        print("") 

        if curr_addr == dest_ip:
            break

    if os.name == 'nt':
        recv_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    recv_socket.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit()
    start_trace(sys.argv[1])
