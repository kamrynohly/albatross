import requests

def scrape_public_dns(country_code, numOfServers):
    # from Public-DNS.info site, json per each country in the world
    url = f"https://public-dns.info/nameserver/{country_code}.json"

    # Send a GET request
    response = requests.get(url)

    # Check if request was successful
    if response.status_code == 200:
        servers = response.json()
        reliable_servers = []

        # Print the DNS servers
        for server in servers:
            if server["reliability"] == 1 and server["name"]:
                reliable_servers.append(server)
            if len(reliable_servers) == numOfServers:
                break
        # print(reliable_servers)
        return reliable_servers
    else:
        print("Failed to retrieve data about servers.")
        return []

# scrape_public_dns('us', 3)