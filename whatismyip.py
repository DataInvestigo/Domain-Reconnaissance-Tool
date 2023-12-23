import socket
import requests

def get_private_ip():
    # Create a socket object
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # Connect to a public server (Google DNS) to get the local IP address
        sock.connect(("8.8.8.8", 80))
        private_ip = sock.getsockname()[0]
    except socket.error:
        private_ip = "Could not retrieve private IP address"
    finally:
        # Close the socket
        sock.close()
    
    return private_ip

def get_public_ip():
    try:
        # Use an API service to get the public IP address
        response = requests.get("https://api.ipify.org")
        public_ip = response.text
    except requests.RequestException:
        public_ip = "Could not retrieve public IP address"
    
    return public_ip

def get_location(ip_address):
    try:
        # Use a geolocation API service to get location details
        response = requests.get(f"https://ipapi.co/{ip_address}/json/")
        data = response.json()
        location = f"{data['city']}, {data['region']}, {data['country_name']}"
    except requests.RequestException:
        location = "Could not retrieve location details"
    
    return location

def get_isp(ip_address):
    try:
        # Use a geolocation API service to get ISP details
        response = requests.get(f"https://ipapi.co/{ip_address}/json/")
        data = response.json()
        isp = data['org']
    except requests.RequestException:
        isp = "Could not retrieve ISP details"
    
    return isp

def get_asn(ip_address):
    try:
        # Use a geolocation API service to get ASN details
        response = requests.get(f"https://ipapi.co/{ip_address}/json/")
        data = response.json()
        asn = data['asn']
    except requests.RequestException:
        asn = "Could not retrieve ASN details"
    
    return asn

def get_latitude_longitude(ip_address):
    try:
        # Use a geolocation API service to get latitude and longitude values
        response = requests.get(f"https://ipapi.co/{ip_address}/json/")
        data = response.json()
        latitude = data['latitude']
        longitude = data['longitude']
    except requests.RequestException:
        latitude = "Could not retrieve latitude"
        longitude = "Could not retrieve longitude"
    
    return latitude, longitude

# Fetch and display the private IP address
private_ip = get_private_ip()
print("Private IP address:", private_ip)

# Fetch and display the public IP address
public_ip = get_public_ip()
print("Public IP address:", public_ip)

# Fetch and display location details
location = get_location(public_ip)
print("Location:", location)

# Fetch and display ISP details
isp = get_isp(public_ip)
print("ISP:", isp)

# Fetch and display ASN details
asn = get_asn(public_ip)
print("ASN:", asn)

# Fetch and display latitude and longitude values
latitude, longitude = get_latitude_longitude(public_ip)
print("Latitude:", latitude)
print("Longitude:", longitude)
