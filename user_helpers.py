import requests
import matplotlib.pyplot as plt
import numpy as np

"""
user_helpers.py

On a user's side, contains helper functions to assist in sending information to Albatross.
"""


# get_user_country()
#
#   Returns a string of the user's country code.
# 
#   Sends a request to ipinfo.io/json in order to get the information about the user's IP address.
#   The user's IP address indicates their present location from which we extract their country code.
#   This allows us to properly equip to Albatross layer to accurately find other DNS servers near their location.
#
#   Ex: `print(get_user_country())`.

def get_user_country():
    try:
        # Make a request to an IP geolocation API to help us get our location.
        response = requests.get('https://ipinfo.io/json')
        data = response.json()

        # Get location data.
        country = data.get('country')
        return country
    except Exception as e:
        # Showcase any errors that may occur, and default to a specified location.
        print(f"error occurred trying to get user location, defaulting to U.S: {str(e)}")
        return "us"


# valid_query(domain)
#
#   Accepts a domain of a website.
#   Returns a boolean of true if we care about the site, or false to ignore it.
# 
#   For example, for the sake of convenience and clarity, we can remove some popular but unnecessary
#   queries, like a query for Google Fonts.
#
#   Ex: `valid_query("www.youtube.com")`.

def valid_query(domain):
    valid_roots = [".com", ".edu", ".gov", ".org", ".net", ".info"]
    ignore_list = ["lh3", "rr3", "fontawesome", "clients4", "printer", "fonts"]
    valid = False
    for root in valid_roots:
        if root in domain:
            valid = True
    for item in ignore_list:
        if item in domain:
            valid = False
    return valid

  
# visualize_results(data)
#
#   Accepts the "warnings" data sent back to the user by Albatross.
#   Creates and opens a visualizing tool to give the user a visual representation 
#   of the potentially unsafe IPs.

def visualize_results(data):
    graph_data = {}
    for item in data:
        domain = item["domain"]
        matches = item["matches"]
        close = item["close_matches"]
        total = item["total"]
        graph_data[domain] = [total-matches-close, close, matches]

    # Get our domain information and match counts.
    domains = list(graph_data.keys())
    match_counts = list(graph_data.values())
    num_domains = len(domains)

    # Define categories of graph.
    categories = ['No Matches', 'Close Matches', 'Exact Matches']
    colors = ["Red", "Orange", "Green"]
    num_categories = len(categories)

    # Plotting our graph.
    figure, ax = plt.subplots()
    bar_height = 0.2
    opacity = 0.8

    index = np.arange(num_domains)
    bar_offset = [-bar_height, 0, bar_height]

    for i in range(num_categories):
        ax.barh(index + bar_offset[i], 
                [match_counts[domain_idx][i] for domain_idx in range(num_domains)], 
                bar_height,
                alpha=opacity,
                color=colors[i].lower(),
                label=categories[i])

    # Format the labels of our graph.
    ax.set_ylabel('Domains')
    ax.set_xlabel('Counts')
    ax.set_title('Albatross Domain Validations')
    ax.set_yticks(index)
    ax.set_yticklabels(domains)
    ax.legend()

    # Show the graph.
    plt.tight_layout()
    plt.show()
