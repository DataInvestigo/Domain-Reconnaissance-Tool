import dns.resolver
import dns.exception
import dns.rdatatype as rdtypes

def check_dns_records(domain, record_type=None):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1

    if record_type:
        record_types = [record_type.upper()]
    else:
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'CAA', 'TXT']

    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            if record_type == 'A':
                print(f"IP Addresses (A records) for {domain}:")
                for rdata in answers:
                    print(f"{rdata.address} TTL={answers.rrset.ttl}")
            elif record_type == 'MX':
                print(f"Mail Exchangers (MX records) for {domain}:")
                for rdata in answers:
                    preference = rdata.preference
                    exchange = rdata.exchange.to_text()
                    print(f"Preference {preference}: {exchange} TTL={answers.rrset.ttl}")
            elif record_type == 'SRV':
                print(f"Service Records (SRV records) for {domain}:")
                for rdata in answers:
                    priority = rdata.priority
                    weight = rdata.weight
                    port = rdata.port
                    target = rdata.target.to_text()
                    print(f"Priority {priority}, Weight {weight}, Port {port}, Target {target} TTL={answers.rrset.ttl}")
            elif record_type == 'SOA':
                print(f"Start of Authority (SOA) record for {domain}:")
                for rdata in answers:
                    mname = rdata.mname.to_text()
                    rname = rdata.rname.to_text()
                    serial = rdata.serial
                    refresh = rdata.refresh
                    retry = rdata.retry
                    expire = rdata.expire
                    minimum = rdata.minimum
                    print(f"MNAME={mname}, RNAME={rname}, Serial={serial}, Refresh={refresh}, Retry={retry}, Expire={expire}, Minimum={minimum} TTL={answers.rrset.ttl}")
            else:
                print(f"{record_type} records for {domain}:")
                for rdata in answers:
                    print(f"{rdata.to_text()} TTL={answers.rrset.ttl}")
            print()
        except dns.resolver.NoAnswer:
            print(f"No {record_type} records found for {domain}")
        except dns.resolver.NXDOMAIN:
            print(f"Domain {domain} does not exist")
        except dns.resolver.Timeout:
            print(f"Timeout occurred while resolving {domain}")
        except dns.rdatatype.UnknownRdatatype:
            print(f"Unknown record type: {record_type}")
        except dns.exception.DNSException as e:
            print(f"Error occurred while resolving {domain}: {str(e)}")

# Example usage
if __name__ == "__main__":
    domain = input("Enter the domain name: ")
    record_type = input("Enter the DNS record type (optional, leave blank to show all record types): ").upper()
    check_dns_records(domain, record_type)
