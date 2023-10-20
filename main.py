from colorama import init as colorama_init
from colorama import Fore
from colorama import Style

from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import ipaddress
import re
from prettytable import PrettyTable

import threading
import socket
from queue import Queue
from time import sleep

def scanmain():
    print(f"{Fore.YELLOW}Welcome to Network Scanner\n{Style.RESET_ALL}")
    try:
        print(f"{Fore.YELLOW}[*] If a single IP address is given, the tool will perform a port scan.")
        print(f"[*] If a single IP address is given, the tool will perform a host discovery.{Style.RESET_ALL}\n")
        while True:
            ip = input(str("[+] Please Enter IP/CIDR Address : "))
            if (is_ipv4(ip) == "Scan"):
                scan(ip)
                break
            elif (is_ipv4(ip) == "Port"):
                port_scan_main(ip)
                break
            else:
                print(f"{Fore.RED}[!] Please enter a valid IP address{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Redirecting to main menu...{Style.RESET_ALL}")
        sleep(3)

def is_ipv4(string):
    try:
        ipaddress.IPv4Network(string)
        return "Port"
    except ValueError:
        cider1 = re.compile(r'^([0-9]{1,3}\.){3}[0-9]{1,3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$')
        cider = cider1.search(string)
        if cider:
            return "Scan"
        else:
            return "Not a valid IP address"

def scan(ipaddress):
    #Create ARP Request
    arp_request = scapy.all.ARP(pdst=ipaddress)
    print(arp_request.summary())
    scapy.all.ls(scapy.all.ARP())
    arp_request.show()
    # Set MAC to Broadcast
    broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
    scapy.all.ls(scapy.all.Ether())
    print(broadcast.summary())
    broadcast.show()
    arp_request_boroadcast = broadcast/arp_request
    arp_request_boroadcast.show()
    #Send packet and get a response
    answered = scapy.all.srp(arp_request_boroadcast, timeout=.5, verbose=0)[0]
    print(answered.summary())
    print(unanswered.summary())
    #Parse the results
    print(answered)
    print("[+] No of nodes present of the Network : ", len(answered))
    print_result_node(answered)

def print_result_node(answered):
    t = PrettyTable([f'{Fore.GREEN}IP Address',f'MAC Address{Style.RESET_ALL}'])
    for node in answered:
        # print(node[1].show())
        # print(node[1].psrc)
        # print(node[1].hwsrc)
        t.add_row([node[1].psrc,node[1].hwsrc])
    print(t)


#Global Variables
target = ""
queue = Queue()
open_ports = []

def port_scan_main(ipaddress):
    arp_request = scapy.all.ARP(pdst=ipaddress)
    broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_boroadcast = broadcast/arp_request
    answered = scapy.all.srp(arp_request_boroadcast, timeout=.5, verbose=0)[0]
    if answered:
        print(f"{Fore.BLUE}[*] Host Is Up!{Style.RESET_ALL}")
        Threads = int(input("[+] Enter # of threads : "))
        t = PrettyTable([f'[{Fore.GREEN}TYPE',f'Description{Style.RESET_ALL}]'])
        t.add_row(["1","Select this mode to scan ports 1 to 1024"])
        t.add_row(["2","Select this mode to scan ports 1 to 49152"])
        t.add_row(["3","Select this mode to scan ports 20,21,22,23,25,53,80,110,443"])
        t.add_row(["4","Select this for a custom port scan"])
        print(t)
        mode = int(input(f"{Fore.WHITE}[+] Enter Mode:{Style.RESET_ALL}"))
        global target
        target = ipaddress
        run_scanner(Threads,mode)
    else:
        print(f"{Fore.YELLOW}[*] Host Is Down!{Style.RESET_ALL}")

def run_scanner(threads, mode):
    get_ports(mode)
    thread_list = []
    for t in range(threads):
        thread = threading.Thread(target=worker)
        thread_list.append(thread)
    for thread in thread_list:
        thread.start()
    for  thread in thread_list:
        thread.join()
    print("[*] Open ports are:", open_ports)
    open_ports.clear()

def get_ports(mode):
    #Port Selection
    if mode == 1:
        for port in range(1, 1024):
            queue.put(port)
    elif mode == 2:
        for port in range(1, 49152):
            queue.put(port)
    elif mode == 3:
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 443]
        for port in ports:
            queue.put(port)
    elif mode == 4:
        ports = input("[+] Enter your ports (seperated by blanks):")
        ports = ports.split()
        ports = list(map(int, ports))
        for port in ports:
            queue.put(port)

def worker():
    while not queue.empty():
        port = queue.get()
        if portscan(port):
            print("[*] Port {} is open!".format(port))
            open_ports.append(port)

def portscan(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target,port))
        return True
    except:
        return False

scanmain()
