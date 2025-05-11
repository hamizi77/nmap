# nmap

#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool")
print(
    r"""
+---------------------------------------------------------+
|            _               _          _       _     _   |
|  ___ _   _| |__   ___ _ __| | ___ __ (_) __ _| |__ | |_ |
| / __| | | | '_ \ / _ \ '__| |/ / '_ \| |/ _` | '_ \| __||
|| (__| |_| | |_) |  __/ |  |   <| | | | | (_| | | | | |_ |
| \___|\__, |_.__/ \___|_|  |_|\_\_| |_|_|\__, |_| |_|\__||
|      |___/                              |___/           |
+---------------------------------------------------------+
"""
)


ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: ", ip_addr)
type(ip_addr)
print("1) syn ack scan\n2) udp scan\n3)comprehensive scan")
resp = input("please enter the type of scan you want to perform in knight_recon:")

print("You have selected option: ", resp)
resp_dict = {
    "1": ["-v -sS", "tcp"],
    "2": ["-v -sU", "udp"],
    "3": ["-v -sS -sV -sC -A -O", "tcp"],
}
if resp not in resp_dict.keys():
    print("enter a valid option")
else:
    print("nmap version: ", scanner.nmap_version())
    scanner.scan(
        ip_addr, "1-1024", resp_dict[resp][0]
    )  # the # are port range to scan, the last part is the scan type
    print(scanner.scaninfo())
    if scanner.scaninfo() == "up":
        print("Scanner Status: ", scanner[ip_addr].state())
        print("All Protocols: ", scanner[ip_addr].all_protocols())
        print("Open Ports: ", scanner[ip_addr][resp_dict[resp][1]].keys())
