import socket
import ssl
import OpenSSL
import datetime
import dns.resolver
import requests
import pymongo
import string
import random
import time

# Variables Defined
MONGODB_CONNECTION_STRING = 'mongodb+srv://lokeshsekar23:lokesh23@datainvestigo.uffk6wq.mongodb.net/'
MONGODB_DATABASE_NAME = 'DataInvestigo'
MONGODB_COLLECTION_NAME = 'SSLexpiry'
OTP_EXPIRY_MINUTES = 1
SENDINBLUE_API_KEY = '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'
SENDER_EMAIL = 'datainvestigo@gmail.com'
otp = None
otp_timestamp = None

headers = {
    'api-key': SENDINBLUE_API_KEY,
    'Content-Type': 'application/json'
}

def connect_to_mongodb():
    try:
        # Connect to MongoDB using the provided connection string
        client = pymongo.MongoClient(MONGODB_CONNECTION_STRING)
        # Get the specified database
        db = client[MONGODB_DATABASE_NAME]
        # Get the specified collection
        collection = db[MONGODB_COLLECTION_NAME]
        return collection
    except pymongo.errors.ConnectionFailure as e:
        print(f"Failed to connect to MongoDB: {e}")
        return None

def save_certificate_details_to_db(certificate_details, recipient_email):
    collection = connect_to_mongodb()
    if collection is not None:
        try:
            # Add recipient email to the certificate details
            certificate_details["Recipient Email"] = recipient_email
            # Insert the certificate details to the MongoDB collection
            collection.insert_one(certificate_details)
            print("Certificate details saved to MongoDB successfully.")
        except pymongo.errors.PyMongoError as e:
            print(f"Failed to insert certificate details to MongoDB: {e}")
    else:
        print("Failed to connect to MongoDB. Certificate details not saved.")

def fetch_cname_record(hostname):
    try:
        answers = dns.resolver.resolve(hostname, 'CNAME')
        cname_record = answers[0].target.to_text(omit_final_dot=True)
        return cname_record
    except dns.resolver.NXDOMAIN:
        return None
    except dns.exception.DNSException as e:
        return f"DNS Error: {e}"

def fetch_local_issuer_certificate(hostname, port):
    try:
        sock = socket.create_connection((hostname, port))
        pem_cert = ssl.get_server_certificate((hostname, port), ssl_version=ssl.PROTOCOL_TLS)
        return pem_cert
    except socket.error as e:
        return {"error": f"Socket Error: {e}"}

def fetch_local_issuer_certificate_details(hostname, port):
    try:
        ip_address = socket.gethostbyname(hostname)
        pem_cert = fetch_local_issuer_certificate(hostname, port)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)

        subject = x509.get_subject()
        issuer = x509.get_issuer()

        common_name = subject.CN
        organization_issued_to = subject.O
        organization_unit_issued_to = subject.OU
        organization_issued_by = issuer.O
        organization_unit_issued_by = issuer.OU

        valid_from = datetime.datetime.strptime(x509.get_notBefore().decode(), "%Y%m%d%H%M%SZ")
        valid_to = datetime.datetime.strptime(x509.get_notAfter().decode(), "%Y%m%d%H%M%SZ")

        key_size = x509.get_pubkey().bits()

        san_list = []
        ext_count = x509.get_extension_count()
        for i in range(ext_count):
            ext = x509.get_extension(i)
            if b"subjectAltName" in ext.get_short_name():
                san_data = ext.__str__()
                san_list = san_data.split(", ")
                break

        cn_match = (common_name == hostname)

        wildcard_domain = None
        if common_name.startswith("*."):
            wildcard_domain = common_name[2:]

        cn_is_wildcard_and_matches = False
        if wildcard_domain and hostname.endswith(wildcard_domain):
            cn_is_wildcard_and_matches = True

        certificate_details = {
            "Domain": hostname,
            "Common Name (CN)": common_name,
            "CNAME Record": None,
            "IP Address": ip_address,
            "Organization (O) - Issued To": organization_issued_to,
            "Organization Unit (OU) - Issued To": organization_unit_issued_to,
            "Organization (O) - Issued By": organization_issued_by,
            "Organization Unit (OU) - Issued By": organization_unit_issued_by,
            "Valid from": valid_from,
            "Valid to": valid_to,
            "Days until expiry": (valid_to - datetime.datetime.utcnow()).days,
            "SSL Key Size": key_size,
            "Subject Alternative Names (SANs)": san_list,
            "CN and Hostname Match": cn_match,
            "Wildcard Domain": wildcard_domain,
            "CN is Wildcard and Matches with Subdomain": cn_is_wildcard_and_matches
        }

        cname_record = fetch_cname_record(hostname)
        if cname_record is not None and not cname_record.startswith("DNS Error"):
            certificate_details["CNAME Record"] = cname_record

        return certificate_details

    except socket.error as e:
        return {"error": f"Socket Error: {e}"}

def fetch_certificate_chain(hostname, port):
    try:
        sock = socket.create_connection((hostname, port))
        context = ssl.create_default_context()
        with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
            der_cert = ssl_sock.getpeercert(True)

        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der_cert)
        chain = [OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, x509).decode()]

        while True:
            issuer = x509.get_issuer()
            subject = x509.get_subject()
            if issuer.CN == subject.CN:
                break
            if not context.get_ca_certs() or not isinstance(context.get_ca_certs()[0], OpenSSL.crypto.X509):
                break
            for cert in context.get_ca_certs():
                if cert.get_subject() == issuer:
                    chain.append(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert).decode())
                    x509 = cert
                    break
            else:
                break

        return chain

    except socket.error as e:
        return {"error": f"Socket Error: {e}"}

def print_certificate_verification_error(exception):
    print("Certificate Verification Error:", exception)
    print("Please check the SSL certificate with a proper bundle file or consider adding proper certificate verification for secure communication.")

def send_reminder_email(domain_name, days_left, recipient_email):
    url = "https://api.sendinblue.com/v3/smtp/email"
    data = {
        "sender": {"email": SENDER_EMAIL},
        "to": [{"email": recipient_email}],
        "templateId": 11,
        "params": {"domain_name": domain_name, "days_left": days_left}
    }
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 201:
        print("Reminder email sent successfully.")
    else:
        print(f"Failed to send reminder email. Error: {response.text}")

def send_email_with_otp(email, otp):
    url = "https://api.sendinblue.com/v3/smtp/email"
    data = {
        'sender': {
            'name': 'Admin',
            'email': SENDER_EMAIL
        },
        'to': [
            {
                'email': email
            }
        ],
        'templateId': 6,  # Replace with the ID of your template
        'params': {
            'otp': otp  # Pass the OTP as a parameter to the email template
        }
    }

    current_time = time.time()
    global otp_timestamp

    # If OTP timestamp is not set or the OTP has expired, send a new OTP
    if not otp_timestamp or (current_time - otp_timestamp) > OTP_EXPIRY_MINUTES * 60:
        otp = generate_otp()
        otp_timestamp = current_time  # Update the OTP timestamp
    else:
        print("Resending the same OTP.")

    response = requests.post(url, json=data, headers=headers)

    if response.status_code == 201:
        print('Email sent successfully!')
    else:
        print('Failed to send email:', response.json())

def resend_email_with_otp(email, otp):
    url = "https://api.sendinblue.com/v3/smtp/email"
    data = {
        'sender': {
            'name': 'Admin',
            'email': SENDER_EMAIL
        },
        'to': [
            {
                'email': email
            }
        ],
        'templateId': 8,  # Use the new template ID (replace with the desired template ID)
        'params': {
            'otp': otp  # Pass the OTP as a parameter to the email template
        }
    }

    response = requests.post(url, json=data, headers=headers)

    if response.status_code == 201:
        print('Email sent successfully!')
    else:
        print('Failed to send email:', response.json())

def is_certificate_expiring_soon(valid_to_date, days_threshold):
    """Check if the certificate is about to expire within the given threshold."""
    remaining_days = (valid_to_date - datetime.datetime.utcnow()).days
    return 0 < remaining_days <= days_threshold

def get_recipient_email():
    recipient_email = input("Enter the recipient email address for reminder: ")
    return recipient_email.strip()

def fetch_and_send_reminder(hostname, local_issuer_certificate, recipient_email):
    days_left = (local_issuer_certificate["Valid to"] - datetime.datetime.utcnow()).days
    enable_reminder = input("Do you want to enable the reminder email? (yes/no): ").lower()
    if enable_reminder == 'yes':
        reminder_threshold = int(input("Enter the number of days before expiry to send the reminder: "))
        if is_certificate_expiring_soon(local_issuer_certificate["Valid to"], reminder_threshold):
            send_reminder_email(hostname, days_left, recipient_email)
        else:
            print("Reminder not sent as the certificate is not about to expire within the specified threshold.")
    else:
        print("Reminder email not enabled.")

def generate_otp(length=6):
    characters = string.digits
    otp = ''.join(random.choice(characters) for i in range(length))
    return otp

def verify_otp(entered_otp, expected_otp, otp_timestamp):
    if entered_otp == expected_otp:
        current_time = time.time()
        time_difference = current_time - otp_timestamp
        if time_difference <= OTP_EXPIRY_MINUTES * 60:
            return True
        else:
            print("OTP has expired. Please generate a new OTP.")
            return False
    else:
        print("Incorrect OTP.")
        return False


def login(url, username):
    try:
        max_attempts = 3
        reset_password_attempt = 0

        while max_attempts > 0:
            # Prompt the user to enter their password
            password = input("Enter your password: ")
            # Construct the URL with the provided username and password as query parameters
            login_url = f"{url}?username={username}&password={password}"

            # Send the HTTP POST request to perform the login
            response = requests.post(login_url)

            # Check the response status code to handle possible errors
            if response.json().get('login_status') == ['Login successful.']:
                # Login successful
                print("Login successful!")
                print("Response:")
                print(response.json())
                return True
            elif response.json().get('login_status') == ['Invalid password.']:
                # Invalid password
                max_attempts -= 1
                print(f"Invalid password. Attempts left: {max_attempts}")
                if max_attempts == 0:
                    # If maximum login attempts reached, offer to reset password
                    print("Maximum login attempts reached. Reset your password and try again.")
                    reset_password_attempt = input("Reset password? (yes/no): ").lower()
                    if reset_password_attempt == 'yes':
                        print("Reset password process...")
                        # Add the code for password reset here
                    return False
            elif response.json().get('login_status') == ['User does not exist.']:
                # User does not exist
                max_attempts -= 1
                print(f"User does not exist. Attempts left: {max_attempts}")
                username = input("Enter your username: ")


                if max_attempts == 0:
                    # If maximum login attempts reached, terminate the program
                    print("Maximum login attempts reached. Exiting the program.")
                    return False
            else:
                # Other login errors
                print(f"Login failed. Error: {response.text}")
                return False
        return False

    except requests.RequestException as e:
        # Handle any exceptions that might occur during the request
        print("An error occurred during the login request.")
        print(e)
        return False

def main():
    global otp, otp_timestamp  # Define the global variables to track OTP and its timestamp

    port = 443

    # Prompt the user to enter their username and password
    username = input("Enter your username: ")
    login_url = "https://daa2-136-185-30-244.ngrok-free.app/Login"

    if not login(login_url, username):
        print("Exiting the program.")
        return

    hostname = input("Enter the domain name (e.g., google.com): ")
    recipient_email = get_recipient_email()
    otp = generate_otp()
    send_email_with_otp(recipient_email, otp)  # Pass the OTP to the function
    entered_otp = input("Enter the OTP received in your email: ")
    if verify_otp(entered_otp, otp, otp_timestamp):
        print("OTP verification successful. Proceed with other tasks.")
    else:
        print("OTP verification failed. Exiting.")
        return
    local_issuer_certificate = fetch_local_issuer_certificate_details(hostname, port)

    if isinstance(local_issuer_certificate, dict) and 'error' in local_issuer_certificate:
        print(f"Error: {local_issuer_certificate['error']}")
        print("Entered Incorrect Domain name, Check and provide the Domain name with proper TLD's with .com, .in, .org, etc..")
    else:
        print(f"Certificate Details for {hostname}:")
        if local_issuer_certificate["CNAME Record"] is not None:
            print(f"CNAME Record: {local_issuer_certificate['CNAME Record']}")
        else:
            print(f"IP Address: {local_issuer_certificate['IP Address']}")

        if local_issuer_certificate.get("CN is Wildcard and Matches with Subdomain"):
            print("The Common Name (CN) is a wildcard and matches the provided subdomain.")

        if local_issuer_certificate.get("CN and Hostname Match"):
            print("The Common Name (CN) matches the provided hostname.")
        else:
            print("The Common Name (CN) does not match the provided hostname.")

        print("-----------------------------------------------------------------\n")

        # Print Valid from and Valid to details
        print(f"Valid from: {local_issuer_certificate['Valid from']}")
        print(f"Valid to: {local_issuer_certificate['Valid to']}")
        print(f"Days until expiry: {local_issuer_certificate['Days until expiry']}")

        # Set reminder start days left as user input
        otp = generate_otp()  # Generate a random OTP
        fetch_and_send_reminder(hostname, local_issuer_certificate, recipient_email)

        print(f"SSL Key Size: {local_issuer_certificate['SSL Key Size']} bits")

        # Subject Alternative Names (SANs)
        san_list = local_issuer_certificate["Subject Alternative Names (SANs)"]
        if san_list:
            print("Subject Alternative Names (SANs):")
            for san in san_list:
                print(san)
        else:
            print("Subject Alternative Names (SANs): None")

        # Wildcard Domain
        wildcard_domain = local_issuer_certificate["Wildcard Domain"]
        if wildcard_domain:
            print(f"Wildcard Domain: {wildcard_domain}")
        else:
            print("Wildcard Domain: None")

        # CN is Wildcard and Matches with Subdomain
        cn_is_wildcard_and_matches = local_issuer_certificate["CN is Wildcard and Matches with Subdomain"]
        if cn_is_wildcard_and_matches:
            print("CN is Wildcard and Matches with Subdomain: Yes")
        else:
            print("CN is Wildcard and Matches with Subdomain: No")

        print("-----------------------------------------------------------------\n")

        try:
            # SSL Certificate Verification
            response = requests.get(f"https://{hostname}:{port}/", verify=True)
            if response.ok:
                print("Certificate verified: Yes")
                server_type = response.headers.get("Server")
                if server_type:
                    print(f"Webserver Type: {server_type}")
                else:
                    print("Webserver Type information not available.")
            else:
                print("Certificate verify failed:", response.reason)
                print("Need to check SSL to avoid threats.")

            # Ask if user wants to see complete certificate chain
            show_certificate_chain = input("Do you want to see the complete certificate chain? (yes/no): ").lower()
            if show_certificate_chain == 'yes':
                certificate_chain = fetch_certificate_chain(hostname, port)

                if isinstance(certificate_chain, list) and len(certificate_chain) > 0:
                    print("\nComplete Certificate Chain:")
                    for idx, cert in enumerate(certificate_chain):
                        print(f"Certificate {idx + 1}:")
                        print(cert)
                        print("\n------------------------------------------\n")
                else:
                    print("No Certificate Chain information available.")
        except requests.exceptions.SSLError as e:
            print("Certificate Verification Error: SSL certificate is not correct or not trusted.")
            print("This server's certificate chain is incomplete.")
            print("Do you want more info about the error? (y/n)")
            user_choice = input().strip().lower()
            if user_choice == 'y':
                print_certificate_verification_error(e)
        except requests.exceptions.RequestException as e:
            print("Error fetching server type:", e)

        # Save certificate details to MongoDB
        save_certificate_details_to_db(local_issuer_certificate, recipient_email)

if __name__ == "__main__":
    main()

