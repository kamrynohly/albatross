import sys
from scapy.all import *
from user_helpers import get_user_country, valid_query, visualize_results
from albatross import albatross


"""
albatross_monitor.py

This file exists on a user's computer as a behind-the-scenes DNS monitor. 
The goal of these functionalities is to monitor network traffic to observe any DNS responses.
We then send these responses to our Albatross layer, ideally stored on a separate server that can 
be sent an encrypted HTTP request. The Albatross layer will validate the responses of the original DNS
queries to confirm that no DNS spoofing, hijacking, or lying has occurred by an attacker.
"""


# Keeping state of the user's location & recent queries to avoid duplicates.
recentlySeenDomains = []
user_location = ""


# dns_monitor(packet)
#
#   Takes in a single network packet. 
#   Validates it using Albatross if it contains a DNS Request Response.

def dns_monitor(packet):
    global recentlySeenDomains
    global user_location

    # If we have not already determined the user's location, find it before calling Albatross.
    if not user_location:
        user_location = get_user_country()
        print(f"Location: {user_location}")

    # If this is not the DNS Request Response (DNSRR) of a DNS query, ignore this packet.
    if not DNSRR in packet:
        return
    
    # Keep track of domains seen to avoid duplicate Albatross calls. Reset every 15 domains.
    if len(recentlySeenDomains) > 15:
        recentlySeenDomains = []

    # Handle the DNS response and validate it using Albatross
    if DNS in packet:  
        domain = packet[DNSQR].qname.decode('utf-8')
        # Check if the packet is one that we should monitor. 
        # Otherwise, ignore this packet.
        valid = valid_query(domain)
        if not valid:
            return
        if domain in recentlySeenDomains:
            return
        recentlySeenDomains.append(domain)

        # Formatting info in a presentable manner
        print("*"*50 + "\nPACKET DETECTED\n" + packet.summary() + "\n")
        print(f"DOMAIN REQUESTED:               {domain}")

        # Save and display IP responses from DNS query
        ips = []
        for i in range(packet[DNS].ancount):
            ips.append(packet[DNSRR][i].rdata)
        print(f"ANS:                            {ips}")

        # Validate using Albatross
        print("\nRunning Albatross Validation...\n")
        warnings = albatross(packet, ips, user_location)

    # Formatting info in a presentable manner
    print("\nEND OF PACKET\n" + "*"*50 + "\n\n")
    return warnings


# main
#
#   Begins monitoring DNS traffic. 
#   Can optionally specify the number of packets to validate in one instance.
#           Low frequency has a better chance of quickly spotting a DNS spoofing attack.
#           High frequency can validate more DNS packets with lower risk of missing packets.
#           Default is 100 packets are checked at a time.
# 
#   Usage: python3 albatross_monitor.py
#   Usage: python3 albatross_monitor.py num_packets
    
if __name__ == '__main__':
    interface = 'en0'                   # Specify computer network interface. 
    dns_filter = "udp port 53"          # Filter to only show DNS queries.

    # Determine the frequency of which packets should be validated by Albatross.
    # Default is 100 packets are checked at a time.
    if len(sys.argv) == 2:
        try:
            count = int(sys.argv[1])
        except:
            print("Improper Usage: number of packets must be an integer.")
            sys.exit(1)
    else:
        count = 100

    # Keep track of concerning IP responses.
    warnings = []
    print(f"Looking for DNS queries on interface {interface}...")
    capture = sniff(iface=interface, filter=dns_filter, count=count)
    for packet in capture:
        monitor_response = dns_monitor(packet)
        if monitor_response:
            warnings = warnings + monitor_response
    
    print("\nEnd of validating packets. Showing results...\n")
    visualize_results(warnings)