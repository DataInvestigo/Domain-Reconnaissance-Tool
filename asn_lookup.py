import argparse
from ipwhois import IPWhois
import socket
import ipaddress

def perform_asn_lookup(ip_address):
    obj = IPWhois(ip_address)
    result = obj.lookup_rdap(depth=1)

    # Fetch required ASN details
    asn_registry = result.get('asn_registry')
    asn = result.get('asn')
    asn_cidr = result.get('asn_cidr')
    asn_country_code = result.get('asn_country_code')
    asn_date = result.get('asn_date')
    asn_description = result.get('asn_description')

    print("ASN Details:")
    print(f"ASN Registry: {asn_registry}")
    print(f"ASN: {asn}")
    print(f"ASN CIDR: {asn_cidr}")
    print(f"ASN Country Code: {asn_country_code}")
    print(f"ASN Date: {asn_date}")
    print(f"ASN Description: {asn_description}")

    # Count the number of IP addresses
    ip_network = ipaddress.ip_network(asn_cidr)
    total_ips = ip_network.num_addresses
    print(f"Total IPs for this ASN: {total_ips}")

    # Print AS name
    as_name = result.get('asn_description')
    print(f"AS Name: {as_name}")

def perform_dns_lookup(domain_name):
    try:
        ip_addresses = socket.gethostbyname_ex(domain_name)[-1]
        for ip_address in ip_addresses:
            print(f"DNS lookup for {domain_name}: {ip_address}")
            perform_asn_lookup(ip_address)
    except socket.gaierror:
        print(f"Unable to perform DNS lookup for {domain_name}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Perform ASN lookup for an IP address')
    parser.add_argument('--ip', type=str, help='IP address to perform the ASN lookup')
    parser.add_argument('--domain', type=str, help='Domain name to perform the DNS lookup')
    args = parser.parse_args()

    ip_address = args.ip
    domain_name = args.domain

    if ip_address:
        perform_asn_lookup(ip_address)
    elif domain_name:
        perform_dns_lookup(domain_name)
    else:
        print("Please provide either an IP address or a domain name.")
