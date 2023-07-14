import socket
import subprocess
import requests
import platform

def fetch_public_ip():
    response = requests.get('https://ipinfo.io')
    data = response.json()
    return data['ip']

def fetch_geolocation(api_key, ip):
    url = f"https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ip}&fields=city,state_prov,continent_code,continent_name,country_code2,country_name,latitude,longitude"
    response = requests.get(url)
    data = response.json()
    return data

def fetch_asn_details(ip):
    url = f"http://ip-api.com/json/{ip}"
    response = requests.get(url)
    data = response.json()
    return data

def get_ip_version(ip_address):
    try:
        socket.inet_pton(socket.AF_INET6, ip_address)
        return "IPv6"
    except socket.error:
        pass

    try:
        socket.inet_pton(socket.AF_INET, ip_address)
        return "IPv4"
    except socket.error:
        pass

    return "Unknown"

def get_network_info():
    if platform.system() == "Windows":
        ipconfig_process = subprocess.Popen(['ipconfig', '/all'], stdout=subprocess.PIPE)
    elif platform.system() == "Linux":
        ipconfig_process = subprocess.Popen(['ip', 'addr'], stdout=subprocess.PIPE)
    else:
        ipconfig_process = None

    if ipconfig_process:
        output, _ = ipconfig_process.communicate()
        output = output.decode('utf-8')
        return output
    else:
        return None

def extract_info(output, keyword):
    start_index = output.find(keyword)
    if start_index == -1:
        return None

    value_start = output.find('inet', start_index) + 5
    value_end = output.find('/', value_start)
    value = output[value_start:value_end].strip()
    return value

def fetch_network_details():
    network_info = get_network_info()
    ip_address = extract_info(network_info, "inet")
    subnet_mask = extract_info(network_info, "inet")
    default_gateway = extract_info(network_info, "default via")
    dns_servers = None  # Modify this line to extract DNS servers from the network_info if available

    return ip_address, subnet_mask, default_gateway, dns_servers

api_key = "c88c2469acb6447b8cec893033c8b201"

# Fetching Public IP
public_ip = fetch_public_ip()
print("Public IP Address:", public_ip)

# Fetching Geolocation
geolocation_data = fetch_geolocation(api_key, public_ip)

city = geolocation_data.get("city", "N/A")
state = geolocation_data.get("state_prov", "N/A")
continent_code = geolocation_data.get("continent_code", "N/A")
continent_name = geolocation_data.get("continent_name", "N/A")
country_code = geolocation_data.get("country_code2", "N/A")
country_name = geolocation_data.get("country_name", "N/A")
latitude = geolocation_data.get("latitude", "N/A")
longitude = geolocation_data.get("longitude", "N/A")

print("Continent Code:", continent_code)
print("Continent Name:", continent_name)
print("Country Code:", country_code)
print("Country Name:", country_name)
print("City:", city)
print("State:", state)
print("Latitude:", latitude)
print("Longitude:", longitude)

# Fetching ASN Details
asn_details = fetch_asn_details(public_ip)

asn_number = asn_details.get("as", "N/A")

print("ASN Number:", asn_number)

isp = asn_details.get("isp", "N/A")
organization = asn_details.get("org", "N/A")

print("ISP:", isp)
print("Organization:", organization)

# Fetch IP Version and Network Details using the public IP
public_ip_version = get_ip_version(public_ip)
public_ip_network_details = fetch_network_details()

# Print the Information
print("Public IP Version:", public_ip_version)