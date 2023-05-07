# Sarah Kam and Mai Klooster
# Smith College CSC251 Final Project: Port Scanner
# Test server: glasgow.smith.edu, IP: 131.229.72.13
# References:
#       https://scapy.readthedocs.io/en/latest/usage.html#syn-scans
#       https://scapy.readthedocs.io/en/latest/usage.html#syn-scans

import socket
import scapy.all as scapy
import sys
from port_generation import port_gen
#import scan_functions


from datetime import datetime
import threading

DST_IP = "131.229.72.13"

# # ICMP ping
# ping = scapy.sr1(scapy.IP(dst=DST_IP)/scapy.ICMP())

# if ping == None: #if host isn't alive, exit
#     print("\n\nHost is not alive. Ending Program.\n")
#     sys.exit()
# else:
#     print("\n\nHost is alive.\n")


# depending on options, port_gen provides a certain list
#test_ports = port_gen(subset=True, order=True) # list of ports in order 0-1023
test_ports = [22, 80, 35, 300]


def checkport(dst_ip, port):
    ans = scapy.sr1(scapy.IP(dst=dst_ip)/scapy.TCP(dport=port,flags="S"), timeout = 0.1) #SYN scan 1 port
    # rn: timeout needed to keep it from going on forever. is this bc of the server IP or smth else?
    return ans
    


def syn_scan(dst_ip, ports):
    print("\nSYN scan started at time: "+str(datetime.now()))
    closed_ports = 0

    for port in ports:
        ans = checkport(dst_ip, port)
        
        if ans == None:
            closed_ports += 1
            print("PORT CLOSED")
        else:
            #ans.show()
            print("PORT "+str(port)+" OPEN")
            #print("PORT: "+str(port)+"     PROTOCOL: "+ans[scapy.IP].proto+"     STATE: open"+"     SERVICE: "+ans[scapy.TCP].sport)
            #print("trying again :/")
            #print(ans[scapy.TCP].sport)
            #print(ans[scapy.IP].proto)

            #https://guedou.github.io/talks/2022_GreHack/Scapy%20in%200x30%20minutes.slides.html#/30
            #maketable function

    print("\nAll ports have been scanned.")
    print(str(closed_ports)+" closed ports.")


syn_scan(DST_IP, test_ports)


# #SYN SCAN
# closed_ports = 0
# print("\nSYN scan started at time: "+str(datetime.now()))
# for i in range(len(test_ports)):
#     # SYN scan all ports, ans is answered


#     ans = scapy.sr1(scapy.IP(dst=DST_IP)/scapy.TCP(dport=test_ports[i],flags="S"), timeout = 2) #SYN scan 1 port
#     # rn: timeout needed to keep it from going on forever. is this bc of the server IP or smth else?

    
#     # if ans == None:
#     #     closed_ports += 1
#     # else:
#     #     ans.show()
