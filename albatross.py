import dns.resolver
from scapy.all import *
from albatross_helpers import get_ip_type, get_dns_servers, is_close_match

"""
albatross.py

Runs on the server's side. 
"""


# Store concerning packets.
warnings = []

# albatross(packet, ips, user_location)
#
#   Inputs a DNS response packet, the ips that were specified by the original response, and the user's location.
#   Returns a metric of determining if an IP response by a DNS query looks valid,
#   or returns a warning if an IP address looks as though the DNS query appears to be hijacked/spoofed.
# 
#   Verifies that a packet's IP "looks" correct by querying other DNS servers locally and internationally.
#   Identifies mismatching IP addresses for the same domain.
#   Majority rules if an IP address can be fully trusted.

def albatross(packet, ips, user_location):
    global warnings 

    # Helpful variables.
    matches = 0
    close_matches = 0
    total = 0
    domain = packet[DNSQR].qname.decode('utf-8')
    ip_type = get_ip_type(ips)

    # Call our various DNS servers to find shared matches.
    servers = get_dns_servers(user_location)
    for server in servers:
        tmp_matches, tmp_close_matches, tmp_total = emulateDNS(server, domain, ips, ip_type)
        matches += tmp_matches
        close_matches += tmp_close_matches
        total += tmp_total
    print("\nAlbatross Results:", " " * 8, f"MATCHES: {matches} | CLOSE MATCHES: {close_matches} | DIFFERENT: {total - matches}")

    # Determine if the IP is safe or not.
    if total == 0:
        print("Determination is inconclusive due to division by zero error.")
        determination = "Inconclusive"
    elif (matches / total) >= 0.50:
        determination = "Safe"
    else:
        determination = "Beware"
        warnings.append({"domain": domain, "ips": ips, "matches": matches, "total": total, "close_matches": close_matches})
    print(f"\nDetermination of DNS Result: {determination}")
    return warnings


# emulateDNS(dns_server, domain, ips, type)
#
#   Inputs a dns_server's information, a domain name, the original DNS query's IPs, and the type of IP.
#   Returns the number of IP matches between the emulated DNS server and the original IPs.

def emulateDNS(dns_server, domain, ips, type):
    # Helpful variables.
    matches = 0
    close_matches = 0
    server_name = dns_server["name"]
    server_ip = dns_server["ip"]
    # Specify the resolver we would like to use.
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server_ip]
    # Attempt to use this DNS server to query the domain for the desired type of IP address.
    try:
        response = resolver.query(domain, type)
    except:
        print(f"~~~~~       DNS from server {server_name} failed to get info on: {domain}.")
        return 0, 0
    # Display results and return matches and total number of IPs observed.
    print(f"~~~~~       DNS Response from {server_name}:")
    for rdata in response:
        if str(rdata) in ips:
            matches += 1
        elif is_close_match(str(rdata), ips, type):
            close_matches += 1
        print("~~~~~       ", " "*20, rdata)
    return matches, close_matches, len(response)