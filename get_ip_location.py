import requests

def get_location():
    try:
        # Make a request to an IP geolocation API to help us get our location
        response = requests.get('https://ipinfo.io/json')
        data = response.json()

        # Get necessary location data
        city = data.get('city')
        region = data.get('region')
        country = data.get('country')

        location_info = {
            "City": city, 
            "Region": region, 
            "Country": country}
        return location_info
    except Exception as e:
        return f"Error: {str(e)}"

# Example
# print(get_location())
