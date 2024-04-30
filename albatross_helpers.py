import requests


"""
albatross_helpers.py

On the server's side, contains helper functions for Albatross.
"""


# scrape_public_dns(country_code, numOfServers)
#
#   Inputs a user's country code and the number of servers requested from that location.
#   Returns a list of numOfServers of public DNS servers within the specified location.
# 
#   Utilizes public-dns.info's JSON information, which contains IP addresses of DNS servers 
#   around the world. This is a web-scraper that collects data by requesting the json of a particular
#   country's DNS servers. The website has them wonderfully formatted in json already.

def scrape_public_dns(country_code, numOfServers):
    # Credit to Public-DNS.info. 
    # Requests the JSON of public DNS servers for a specified country.
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
        # Failed to get a valid response from Public-DNS.info, so return an empty list of servers. 
        print("Failed to retrieve data about servers.")
        return []


# get_ip_type(ips)
#
#   Inputs a list of IP addresses.
#   Returns if we should use IPv6 or IPv4.
# 
#   If we detect IPv6 (xxxx:xxxx...), we must use DNS queries of type "AAAA"
#   If we detect IPv4 (xxx.xxx...), we must use DNS queries of type "A"
    
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

def get_dns_servers(location):
    country_code = location.lower()
    all_servers = []

    # Scrape the specified DNS servers...
    all_servers += scrape_public_dns(country_code, 3)
    all_servers += scrape_public_dns("us", 3)
    all_servers += scrape_public_dns("gb", 3)

    # If anything goes wrong and we have no valid servers, return nothing.
    if not all_servers:
        print("Error in getting dns servers...")
        return []
    return all_servers



# Examples of testing the above helper functions:

# Get 3 DNS servers from the U.S.A.
# print(scrape_public_dns('us', 3))

# Determine whether to use IPv6 or IPv4 with a byte string introduced.
# print(get_ip_type([b'sb.l.google.com.', '2607:f8b0:4006:81c::200e']))

# Get DNS servers where the user is based out of Australia or Iran.
# get_dns_servers("au")
# get_dns_servers("ir")