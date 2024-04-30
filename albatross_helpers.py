import requests


"""
albatross_helpers.py

On the server's side, contains helper functions for Albatross.
"""


# scrape_public_dns(country_code, numOfServers)
#
#   Accepts a user's country code and the number of servers requested from that location.
#   Returns a list of numOfServers of public DNS servers within the specified location.
# 
#   Utilizes public-dns.info's JSON information, which contains IP addresses of DNS servers 
#   around the world. This is a web-scraper that collects data by requesting the JSON of a particular
#   country's DNS servers.
#
#   Ex: to get 3 servers from the US, run `print(scrape_public_dns('us', 3))`.

def scrape_public_dns(country_code, numOfServers):
    # Public-DNS.info provides a JSON of public DNS servers for a specified country.
    url = f"https://public-dns.info/nameserver/{country_code}.json"
    response = requests.get(url)

    # Check if request was successful.
    if response.status_code == 200:
        # Keep track of the servers requested.
        servers = response.json()
        reliable_servers = []

        # Specify servers that have high reliability and have a specified name.
        # Store each of these servers until we have the desired number of servers.
        for server in servers:
            if server["reliability"] == 1 and server["name"]:
                reliable_servers.append(server)
            if len(reliable_servers) == numOfServers:
                break
        return reliable_servers
    else:
        # If failed to get a valid response from Public-DNS.info, return an empty list of servers. 
        print("Failed to retrieve data about servers.")
        return []


# get_ip_type(ips)
#
#   Accepts a list of IP addresses.
#   Returns if the IPs are IPv6 or IPv4.
# 
#   If it detects IPv6 (xxxx:xxxx...), DNS queries must be of type "AAAA".
#   If it detects IPv4 (xxx.xxx...), DNS queries must be of type "A".
#
#   Ex: to determine whether to use IPv6 or IPv4 with a byte string introduced, run
#   `print(get_ip_type([b'sb.l.google.com.', '2607:f8b0:4006:81c::200e']))`.
    
def get_ip_type(ips):
    for ip in ips:
        if isinstance(ip, bytes):            # Ignore byte-strings.
            continue    
        if ":" in ip:                        # If we detect a ":", then we know it is IPv6.
            return 'AAAA'
    return 'A'


# get_dns_servers(location)
#
#   Inputs a user's location country.
#   Returns a list of a mixture of the following DNS servers:
#       -- 3 local DNS servers
#       -- 3 DNS servers in the US      (country code "us")
#       -- 3 DNS servers in the UK      (country code "gb")
#
#   Ex: to get DNS servers where the user is based out of Australia, run `get_dns_servers("au")`.

def get_dns_servers(location):
    country_code = location.lower()
    all_servers = []

    # Scrape the specified DNS servers.
    all_servers += scrape_public_dns(country_code, 3)
    all_servers += scrape_public_dns("us", 3)
    all_servers += scrape_public_dns("gb", 3)

    # If anything goes wrong and we have no valid servers, return nothing.
    if not all_servers:
        print("Error in retrieving dns servers.")
        return []
    return all_servers


# is_close_match(originalIP, ips, ipType)
#
#   Accepts a single IP, a list of IPs to compare to, and the type of IP given.
#   Returns a boolean representing if the IP is a "close enough" match.
# 
#   A match is "close enough" if the first IP segment matches and one other segment matches.
#   This attempts to accomodate for companies that own a large range of IP addresses.

def is_close_match(originalIP, ips, ipType):
    if isinstance(originalIP, bytes):
        return False
    for currentIP in ips:
        try:
            # Determine the best way to split into IP segments.
            if ipType == "A":
                original_split = originalIP.split(".")
                current_split = currentIP.split(".")
            if ipType == "AAAA":
                original_split = originalIP.split(":")
                current_split = currentIP.split(":")
            # To be a close match, the first sequence of numbers must match.
            if not original_split[0] in current_split[0]:
                return False
            # To be a close match, one more segment must match besides the first segment.
            for x in original_split[1::]:
                if x in current_split:
                    return True
        except:
            return False
    # Otherwise, assume it is not a close match.
    return False
