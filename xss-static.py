import os
import requests
from urllib.parse import quote
import logging
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm  # For progress bar

# Setting up logging
logging.basicConfig(filename='xss_test_results.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to read payloads from a file
def read_payloads_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            payloads = [line.strip() for line in file if line.strip()]
            if not payloads:
                print(f"Warning: The file '{file_path}' is empty.")
            return payloads
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return []
    except PermissionError:
        print(f"Error: Permission denied when accessing '{file_path}'.")
        return []
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return []

# Function to test for Stored XSS
def test_stored_xss(stored_xss_url, payload, timeout):
    try:
        response = requests.post(stored_xss_url, data={'input': payload}, timeout=timeout)
        response.raise_for_status()  # Check for HTTP errors
        if response.status_code == 404:
            logging.warning(f"Page not found: {stored_xss_url} with payload {payload}")
        elif response.status_code == 500:
            logging.error(f"Server error at {stored_xss_url} with payload {payload}")
        return payload, "<script>" in response.text or "onerror" in response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error with request: {e} for payload: {payload}")
        return payload, False

# Function to test for Reflected XSS
def test_reflected_xss(reflected_xss_url, payload, timeout):
    try:
        response = requests.get(reflected_xss_url + quote(payload), timeout=timeout)
        response.raise_for_status()  # Check for HTTP errors
        if response.status_code == 404:
            logging.warning(f"Page not found: {reflected_xss_url} with payload {payload}")
        elif response.status_code == 500:
            logging.error(f"Server error at {reflected_xss_url} with payload {payload}")
        return payload, "<script>" in response.text or "onerror" in response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error with request: {e} for payload: {payload}")
        return payload, False

# Function to run stored and reflected XSS tests concurrently
def run_tests_concurrently(stored_xss_url, reflected_xss_url, payloads, timeout):
    stored_vulnerabilities = 0
    reflected_vulnerabilities = 0

    with ThreadPoolExecutor(max_workers=5) as executor:
        # Run Stored XSS tests
        stored_results = executor.map(lambda payload: test_stored_xss(stored_xss_url, payload, timeout), payloads)
        for payload, result in tqdm(stored_results, total=len(payloads), desc="Testing Stored XSS", ncols=100):
            if result:
                logging.info(f"[+] Stored XSS Vulnerability Found with Payload: {payload}")
                print(f"[+] Stored XSS Vulnerability Found with Payload: {payload}")
                stored_vulnerabilities += 1
            else:
                logging.info(f"[-] No Stored XSS Vulnerability Detected with Payload: {payload}")

        # Run Reflected XSS tests
        reflected_results = executor.map(lambda payload: test_reflected_xss(reflected_xss_url, payload, timeout), payloads)
        for payload, result in tqdm(reflected_results, total=len(payloads), desc="Testing Reflected XSS", ncols=100):
            if result:
                logging.info(f"[+] Reflected XSS Vulnerability Found with Payload: {payload}")
                print(f"[+] Reflected XSS Vulnerability Found with Payload: {payload}")
                reflected_vulnerabilities += 1
            else:
                logging.info(f"[-] No Reflected XSS Vulnerability Detected with Payload: {payload}")

    return stored_vulnerabilities, reflected_vulnerabilities

def print_summary(total_payloads, stored_vulnerabilities, reflected_vulnerabilities):
    print("\n--- Summary of XSS Testing ---")
    print(f"Total Payloads Tested: {total_payloads}")
    print(f"Stored XSS Vulnerabilities Found: {stored_vulnerabilities}")
    print(f"Reflected XSS Vulnerabilities Found: {reflected_vulnerabilities}")
    logging.info(f"Total Payloads Tested: {total_payloads}")
    logging.info(f"Stored XSS Vulnerabilities Found: {stored_vulnerabilities}")
    logging.info(f"Reflected XSS Vulnerabilities Found: {reflected_vulnerabilities}")

# Function to list and select a payload file
def list_payload_files():
    # Get the current script directory and the payloads folder path relative to it
    script_dir = os.path.dirname(os.path.abspath(__file__))
    payloads_folder = os.path.join(script_dir, 'payloads')

    # Check if the payloads folder exists
    if not os.path.exists(payloads_folder):
        print(f"Error: The payloads folder '{payloads_folder}' does not exist.")
        exit()

    print("\nAvailable Payload Files:")
    payload_files = [f for f in os.listdir(payloads_folder) if f.endswith('.txt')]

    if not payload_files:
        print(f"No .txt payload files found in {payloads_folder}. Exiting.")
        exit()

    for idx, file_name in enumerate(payload_files, 1):
        # Display the file names
        print(f"{idx}. {file_name}")
    
    return payloads_folder, payload_files

def get_payload_file():
    # List payload files and choose one
    payloads_folder, payload_files = list_payload_files()
    
    # Ask user to select a file
    try:
        file_choice = int(input("\nSelect a payload file by number: "))
        if 1 <= file_choice <= len(payload_files):
            selected_file = payload_files[file_choice - 1]
            print(f"Selected file: {selected_file}")
            return os.path.join(payloads_folder, selected_file)
        else:
            print("Invalid choice. Exiting.")
            exit()
    except ValueError:
        print("Invalid input. Exiting.")
        exit()

# Function to automatically prepend http:// or https:// to the URL if necessary
def validate_url(url):
    if not url.startswith("http"):
        # If it doesn't start with http or https, assume http:// by default
        return "http://" + url
    return url

def main():
    print("Welcome to the XSS Testing Script!")

    # Get user input for URLs
    stored_xss_url = input("Enter the URL for Stored XSS testing (e.g., example.com/submit): ")
    reflected_xss_url = input("Enter the URL for Reflected XSS testing (e.g., example.com/search?q=): ")

    # Automatically prepend http:// or https:// to the URL if missing
    stored_xss_url = validate_url(stored_xss_url)
    reflected_xss_url = validate_url(reflected_xss_url)

    # List and choose payload file
    payload_file_path = get_payload_file()
    payloads = read_payloads_from_file(payload_file_path)

    # Check if there are any payloads to test
    if not payloads:
        print("No valid payloads found. Exiting.")
        return

    # Get timeout value
    try:
        timeout = float(input("Enter the timeout value for requests (in seconds, e.g., 10): "))
    except ValueError:
        print("Invalid timeout value. Using default timeout of 10 seconds.")
        timeout = 10.0

    # Confirm the user wants to proceed
    proceed = input("\nDo you want to proceed with testing? (yes/no): ")
    if proceed.lower() == 'yes':
        stored_vulnerabilities, reflected_vulnerabilities = run_tests_concurrently(stored_xss_url, reflected_xss_url, payloads, timeout)
        print_summary(len(payloads), stored_vulnerabilities, reflected_vulnerabilities)
    else:
        print("Testing aborted.")

    print("XSS Tests Completed.")

if __name__ == "__main__":
    main()
