# Inspired from ChatGPT
# Keep track of DNS queries by creating a listener.
print("Importing scapy...")
from scapy.all import *
print("Ready to go!\n")
from albatross import albatross
from get_ip_location import get_location

recentlySeenDomains = []
user_location = ""

# Playing around
def dns_observer(packet):
    global recentlySeenDomains
    global user_location

    if not user_location:
        user_location = get_location()
        print(f"LOCATION: {user_location}")

    # DNSRR = DNS Response
    if not DNSRR in packet:
        # If this is not the response of a DNS query, ignore this packet
        return

    if DNS in packet:  # DNS query
        domain = packet[DNSQR].qname.decode('utf-8')
        valid = ".com" in domain or ".edu" in domain or ".org" in domain
        if not valid:
            return
        if len(recentlySeenDomains) > 15:
            recentlySeenDomains = []
        if domain in recentlySeenDomains:
            return
        recentlySeenDomains.append(domain)

        # Some formatting stuff
        print("*" * 50)
        print("PACKET DETECTED")
        print(packet.summary())
        print("\n")
        print(f"DOMAIN REQUESTED:               {domain}")

        if DNSRR in packet:
            response = packet[DNSRR].rrname.decode('utf-8')
            # Response from DNS query
            ips = []
            for i in range(packet[DNS].ancount):
                ips.append(packet[DNSRR][i].rdata)
            print(f"ANS:                            {ips}")
            print("RUNNING ALBATROSS SECURITY...")
            albatross(packet, ips, user_location)

    print("")
    print("END OF PACKET")
    print("*" * 50)
    print("\n\n")

if __name__ == '__main__':
    # Interface depends on the computer you are using. I'm on a Mac
    interface = 'en0'
    BPF_filter = "udp port 53"

    print(f"Looking for DNS queries on interface {interface}...")
    capture = sniff(iface=interface, filter=BPF_filter, count=100)
    print(capture)
    for packet in capture:
        # print(packet)
        dns_observer(packet)
    # sniff(iface=interface, filter=BPF_filter, prn=dns_observer, store=0, count=100)


# Helper link
# https://www.geeksforgeeks.org/packet-sniffing-using-scapy/