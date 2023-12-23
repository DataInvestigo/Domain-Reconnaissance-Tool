import whois

def check_domain_privacy(domain_name):
    try:
        # Fetching domain information
        domain_info = whois.whois(domain_name)
        
        # Check if the privacy is protected
        if domain_info.privacy:
            return f"The domain {domain_name} has privacy protection enabled."
        else:
            return f"The domain {domain_name} does not have privacy protection enabled."
    except Exception as e:
        return f"Error fetching domain information: {e}"

if __name__ == "__main__":
    domain = input("Enter the domain name (e.g., example.com): ")
    result = check_domain_privacy(domain)
    print(result)
