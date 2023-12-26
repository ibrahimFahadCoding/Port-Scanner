import sys
import socket
from datetime import datetime
import pyfiglet
import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients.append(client_dict)
    return clients

def print_results(results_list):
    print("IP\t\t\tMac Address\n-----------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


asciiBanner=pyfiglet.figlet_format("nmap")
print(asciiBanner)
networkip = input(str("Enter Network IP: "))
scan_result = scan(networkip)
print_results(scan_result)
ip = input(str("Enter Target IP: "))
results=[]
print("Scanning {}".format(ip))


try:
    for port in range(1,65535):
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.1)
        result=s.connect_ex((ip,port))

        if result == 0:
            results.append(result)
            print("[*] Port {} is open".format(port))
        s.close()

    if len(results)==0:
        print("[*] No Open Ports")
    print("[*] Scanning Complete")
    sys.exit()

except KeyboardInterrupt:
    print("\n Exiting")
    sys.exit()
except socket.error:
    print("\n Host not responding")
    sys.exit()
    

