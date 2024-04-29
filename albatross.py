# Runs on our server, not the clients.
import dns.resolver
from scapy.all import *
from dns_server_scraper import scrape_public_dns

# Verifies that a packet's IP "looks" correct.
# Takes in a packet and the ips that were specified by the original DNS response.
def albatross(packet, ips, user_location):
    matches = 0
    total = 0
    domain = packet[DNSQR].qname.decode('utf-8')

    # Call our varying DNS servers to find shared matches.
    servers = get_dns_servers(user_location)
    for server in servers:
        tmp_matches, tmp_total = emulateDNS(server, domain, ips)
        matches += tmp_matches
        total += tmp_total
    print("")
    print(f"Albatross Results:", f" " * 8, f"MATCHES: {matches} | DIFFERENT: {total - matches}")
    print("\nDetermination of DNS Result: ???")


def emulateDNS(dns_server, domain, ips):
    matches = 0
    server_name = dns_server["name"]
    server_ip = dns_server["ip"]
    # print(f"{server_name} DNS Checking...")
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server_ip]
    try:
        response = resolver.query(domain, 'A')
    except:
        print(f"~~~~~       DNS from server {server_name} failed to get info on: {domain}.")
        return 0, 0
    
    print(f"~~~~~       DNS Response from {server_name}:")
    for rdata in response:
        if str(rdata) in ips:
            matches += 1
        print(f"~~~~~       ", f" "*20, rdata)

    return matches, len(response)



def get_dns_servers(location):
    # print("GET DNS SERVERS")
    country_code = location["Country"].lower()
    # print(f"country code {country_code}")
    local_servers = scrape_public_dns(country_code, 3)
    # non-local servers
    us_servers = scrape_public_dns("us", 3)
    # print("ABOUT TO RETURN")
    if not local_servers or not us_servers:
        print("something went wrong")
        if not (not local_servers) and not us_servers:
            return local_servers
        elif not (not us_servers):
            return us_servers
    results = local_servers + us_servers
    # print(f"final servers {results}")
    return results

