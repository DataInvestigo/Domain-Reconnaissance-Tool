import requests
import socket

def reverse_ip_lookup(ip_or_domain):
    try:
        # Check if the input is an IP address or a domain name
        if ip_or_domain.replace(".", "").isdigit():  # IP address contains only digits and dots
            ip_address = ip_or_domain
        else:  # Resolve domain name to IP address
            ip_address = socket.gethostbyname(ip_or_domain)
        
        api_key = "413f7b13956242"  # You need to sign up on ipinfo.io to get an API key
        base_url = f"https://ipinfo.io/{ip_address}/json?token={api_key}"
        
        response = requests.get(base_url)
        data = response.json()
        
        if "ip" in data:
            print(f"IP Address: {data['ip']}")
            print(f"Hostname: {socket.gethostbyaddr(data['ip'])[0]}")
            print(f"City: {data.get('city', 'N/A')}")
            print(f"Region: {data.get('region', 'N/A')}")
            print(f"Country: {data.get('country', 'N/A')}")
            print(f"Location: {data.get('loc', 'N/A')}")
            print(f"Organization: {data.get('org', 'N/A')}")
        else:
            print("Unable to fetch information for the given IP address.")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
    except socket.gaierror as e:
        print(f"Error: Unable to resolve the domain name. {e}")

if __name__ == "__main__":
    ip_or_domain = input("Enter an IP address or domain name: ")
    reverse_ip_lookup(ip_or_domain)
