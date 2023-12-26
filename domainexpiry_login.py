import whois
import ssl
import socket
from datetime import datetime
import requests
from pymongo import MongoClient

SENDINBLUE_API_KEY = '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'
REMINDER_TEMPLATE_ID = '9'
SENDER_EMAIL = 'datainvestigo@gmail.com'

# MongoDB configuration
MONGODB_CONNECTION_STRING = 'mongodb+srv://lokeshsekar23:lokesh23@datainvestigo.uffk6wq.mongodb.net/'
MONGODB_DATABASE_NAME = 'DataInvestigo'
MONGODB_COLLECTION_NAME = 'domain_checker'

headers = {
    'api-key': SENDINBLUE_API_KEY,
    'Content-Type': 'application/json'
}

RECIPIENT_EMAIL = ''  # Declare the global variable

def send_reminder_email(domain_name, days_left):
    url = "https://api.sendinblue.com/v3/smtp/email"
    data = {
        "sender": {"email": SENDER_EMAIL},
        "to": [{"email": RECIPIENT_EMAIL}],
        "templateId": REMINDER_TEMPLATE_ID,
        "params": {"domain_name": domain_name, "days_left": days_left}
    }
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 201:
        print("Reminder email sent successfully.")
    else:
        print(f"Failed to send reminder email. Error: {response.text}")

def check_domain_details(domain_name):
    try:
        w = whois.whois(domain_name)
        if w.status:
            status = "Registered"
            expiry_date = w.expiration_date
            creation_date = w.creation_date
            updated_date = w.updated_date
            registrar = w.registrar
            if isinstance(expiry_date, list):
                expiry_date = expiry_date[0]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(updated_date, list):
                updated_date = updated_date[0]
            print(f"Domain: {domain_name}")
            print(f"Status: {status}")
            print(f"Creation Date: {creation_date}")
            print(f"Last Updated Date: {updated_date}")
            print(f"Expiry Date: {expiry_date}")
            print(f"Registrar: {registrar}")

            days_left = (expiry_date - datetime.now()).days
            print(f"Expiry Days Left: {days_left}")

            # Set reminder email 30 days prior to expiration if user selects "Yes"
            reminder = days_left == 30  # Determine if reminder needs to be sent
            if days_left <= 30 and days_left > 0 and RECIPIENT_EMAIL != '' and reminder:
                send_reminder_email(domain_name, days_left)

                # Update reminder status in MongoDB
                update_reminder_status(domain_name, True)  # Pass True to indicate the reminder is set

            # Store the domain details in MongoDB
            store_domain_details(domain_name, status, creation_date, updated_date, expiry_date, registrar, days_left)
        else:
            status = "Not Registered"
            print(f"Domain: {domain_name}")
            print(f"Status: {status}")

        ip_address = socket.gethostbyname(domain_name)
        print(f"IP Address: {ip_address}")
    except Exception as e:
        print(f"An error occurred: {e}")

def store_domain_details(domain_name, status, creation_date, updated_date, expiry_date, registrar, days_left):
    try:
        client = MongoClient(MONGODB_CONNECTION_STRING)
        db = client[MONGODB_DATABASE_NAME]
        collection = db[MONGODB_COLLECTION_NAME]
        domain_data = {
            "domain_name": domain_name,
            "status": status,
            "creation_date": creation_date,
            "updated_date": updated_date,
            "expiry_date": expiry_date,
            "registrar": registrar,
            "days_left": days_left,
            "recipient_email": RECIPIENT_EMAIL
        }
        collection.insert_one(domain_data)
        print("Domain details stored in MongoDB successfully.")
    except Exception as e:
        print(f"Failed to store domain details in MongoDB. Error: {e}")

def update_reminder_status(domain_name, reminder_set):
    try:
        client = MongoClient(MONGODB_CONNECTION_STRING)
        db = client[MONGODB_DATABASE_NAME]
        collection = db[MONGODB_COLLECTION_NAME]
        collection.update_one(
            {"domain_name": domain_name},
            {"$set": {"reminder_set": reminder_set}}
        )
        print("Reminder status updated in MongoDB successfully.")
    except Exception as e:
        print(f"Failed to update reminder status in MongoDB. Error: {e}")

def get_valid_response(prompt, valid_options):
    response = input(prompt)
    while response.lower() not in valid_options:
        print("Invalid response. Please try again.")
        response = input(prompt)
    return response

def login(username, password):
    url = f"https://df10-122-174-205-21.ngrok-free.app/Login?username={username}&password={password}"
    response = requests.get(url)
    if response.status_code == 200:
        print("Login successful.")
        # Store the username in the database
        store_username(username, True)  # Pass True to indicate successful login
        return True
    else:
        print("Login failed.")
        # Store the username in the database
        store_username(username, False)  # Pass False to indicate failed login
        return False

def store_username(username, login_result):
    try:
        client = MongoClient(MONGODB_CONNECTION_STRING)
        db = client[MONGODB_DATABASE_NAME]
        collection = db[MONGODB_COLLECTION_NAME]
        username_data = {
            "username": username,
            "login_result": login_result
        }
        collection.insert_one(username_data)
        print("Username stored in MongoDB successfully.")
    except Exception as e:
        print(f"Failed to store username in MongoDB. Error: {e}")

def main():
    global RECIPIENT_EMAIL  # Declare RECIPIENT_EMAIL as a global variable

    # Prompt the user to login
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    while not login(username, password):
        print("Invalid username or password. Please try again.")
        username = input("Enter your username: ")
        password = input("Enter your password: ")

    # Prompt the user to set a reminder email
    set_reminder = get_valid_response("Do you want to set a reminder email? (Yes/No): ", ["yes", "no"])
    if set_reminder.lower() == 'yes':
        RECIPIENT_EMAIL = input("Enter the recipient email address: ")
        while not RECIPIENT_EMAIL:
            print("Recipient email is mandatory.")
            RECIPIENT_EMAIL = input("Enter the recipient email address: ")

    domain_name = input("Enter the domain name to check: ")
    while not domain_name:
        print("Domain name is mandatory.")
        domain_name = input("Enter the domain name to check: ")

    check_domain_details(domain_name)

    # Update reminder status in MongoDB if the reminder is set
    reminder = set_reminder.lower() == 'yes'
    if reminder and RECIPIENT_EMAIL:
        update_reminder_status(domain_name, True)

if __name__ == "__main__":
    main()
