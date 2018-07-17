#!/usr/bin/env python

import scapy.all as scapy
import re
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--ip-address", dest="ip_address", help="An Ip address")
    parser.add_argument("-m", "--mac-address", dest="mac_address", help="An MAC address ")
    options = parser.parse_args()

    if not options.ip_address:
        parser.error("[-] You have to specify an ip address. Type -h for more info")
    else:
        if not re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", options.ip_address):
            parser.error("[-] You have typed a wrong ip address.")

    if not options.mac_address:
        parser.error("[-] You have to specify aa MAC address. Type -h for more info")
    else:
        if not re.match(r"\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}", options.mac_address):
            parser.error("[-] You have typed a wrong MAC address.")

    return options


def get_client_list():
    arguments = get_arguments()

    arp_request = scapy.ARP(pdst=arguments.ip_address + "/24")
    broadcast = scapy.Ether(dst=arguments.mac_address)
    full_request = broadcast/arp_request
    answered = scapy.srp(full_request, timeout=1, verbose=False)[0]

    client_list = []
    for response in answered:
        client_dictionary = {"mac": response[1].hwsrc, "ip": response[1].psrc}
        client_list.append(client_dictionary)

    return client_list


def print_clients(client_list):
    print("============================================================")
    print("IP\t\t\t\tMAC Address")
    print("============================================================\n")
    for client in client_list:
        print(client["ip"] + "\t\t\t" + client["mac"])
        print("-------------------------------------------------------")


# "ff:ff:ff:ff:ff:ff"
# 10.0.2.1


print_clients(get_client_list())
