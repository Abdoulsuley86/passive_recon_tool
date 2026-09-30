import socket
import subprocess
import urllib.request
import urllib.error
from datetime import datetime


def save_report(domain, content):
    filename = domain + "_full_report.txt"
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(filename, "w") as file:
        file.write("=" * 60 + "\n")
        file.write("                 PASSIVE RECON REPORT\n")
        file.write("=" * 60 + "\n")
        file.write("Target       : " + domain + "\n")
        file.write("Scan Time    : " + scan_time + "\n")
        file.write("Scan Type    : Passive\n")
        file.write("Modules Run  : 4\n")
        file.write("Status       : Complete\n")
        file.write("=" * 60 + "\n\n")

        file.write("SCAN SUMMARY\n")
        file.write("-" * 40 + "\n")
        file.write("IP Information : Collected\n")
        file.write("WHOIS          : Collected\n")
        file.write("DNS            : Collected\n")
        file.write("Web Information: Collected\n\n")

        file.write(content)

        file.write("\n" + "=" * 60 + "\n")
        file.write("                  END OF REPORT\n")
        file.write("=" * 60 + "\n")

    print("\n[+] Report saved to:", filename)


def ip_information(domain):
    try:
        ip = socket.gethostbyname(domain)
        hostname = socket.getfqdn(domain)

        return (
            "\n[IP INFORMATION]\n"
            + "-" * 40 + "\n"
            + "IP Address : " + ip + "\n"
            + "Hostname   : " + hostname + "\n"
        )

    except socket.gaierror:
        return "\n[IP INFORMATION]\nCould not find IP information.\n"


def whois_information(domain):
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.stdout:
            return (
                "\n[WHOIS INFORMATION]\n"
                + "-" * 40 + "\n"
                + result.stdout
            )

        return "\n[WHOIS INFORMATION]\nNo WHOIS information returned.\n"

    except FileNotFoundError:
        return "\n[WHOIS INFORMATION]\nWHOIS is not installed.\n"

    except subprocess.TimeoutExpired:
        return "\n[WHOIS INFORMATION]\nWHOIS request timed out.\n"


def dns_information(domain):
    output = "\n[DNS INFORMATION]\n"
    output += "-" * 40 + "\n"

    for record_type in ["A", "AAAA", "MX", "NS"]:
        try:
            result = subprocess.run(
                ["dig", "+short", record_type, domain],
                capture_output=True,
                text=True,
                timeout=15
            )

            records = result.stdout.strip()

            output += "\n" + record_type + " RECORDS:\n"

            if records:
                output += records + "\n"
            else:
                output += "No records found.\n"

        except FileNotFoundError:
            output += "\ndig is not installed.\n"
            break

        except subprocess.TimeoutExpired:
            output += "\nDNS query timed out.\n"

    return output


def web_information(domain):
    url = "https://" + domain

    try:
        request = urllib.request.Request(
            url,
            method="HEAD",
            headers={"User-Agent": "PassiveReconTool/1.0"}
        )

        with urllib.request.urlopen(request, timeout=10) as response:
            return (
                "\n[WEB INFORMATION]\n"
                + "-" * 40 + "\n"
                + "URL          : " + url + "\n"
                + "Status Code  : " + str(response.status) + "\n"
                + "Server       : "
                + response.headers.get("Server", "Not provided") + "\n"
                + "Content Type : "
                + response.headers.get("Content-Type", "Not provided") + "\n"
            )

    except urllib.error.HTTPError as error:
        return (
            "\n[WEB INFORMATION]\n"
            + "-" * 40 + "\n"
            + "HTTP Error: " + str(error.code) + "\n"
        )

    except urllib.error.URLError:
        return (
            "\n[WEB INFORMATION]\n"
            + "-" * 40 + "\n"
            + "Could not connect to website.\n"
        )

    except TimeoutError:
        return (
            "\n[WEB INFORMATION]\n"
            + "-" * 40 + "\n"
            + "Web request timed out.\n"
        )


def full_scan():
    domain = input("\nEnter domain: ").strip()

    if not domain:
        print("Domain cannot be empty.")
        return

    print("\nStarting full passive scan...")
    print("Target:", domain)

    report = ""

    print("\n[+] Collecting IP information...")
    ip = ip_information(domain)
    print(ip)
    report += ip + "\n"

    print("[+] Collecting WHOIS information...")
    whois = whois_information(domain)
    print(whois)
    report += whois + "\n"

    print("[+] Collecting DNS information...")
    dns = dns_information(domain)
    print(dns)
    report += dns + "\n"

    print("[+] Collecting web information...")
    web = web_information(domain)
    print(web)
    report += web + "\n"

    save_report(domain, report)

    print("\nFull passive scan complete!")


while True:
    print("\n" + "=" * 40)
    print("       PASSIVE RECON TOOL")
    print("=" * 40)
    print("1. IP Information")
    print("2. WHOIS Information")
    print("3. DNS Information")
    print("4. Web Information")
    print("5. Full Passive Scan")
    print("6. Exit")

    choice = input("\nChoose an option: ").strip()

    if choice == "1":
        domain = input("Enter domain: ").strip()
        print(ip_information(domain))

    elif choice == "2":
        domain = input("Enter domain: ").strip()
        print(whois_information(domain))

    elif choice == "3":
        domain = input("Enter domain: ").strip()
        print(dns_information(domain))

    elif choice == "4":
        domain = input("Enter domain: ").strip()
        print(web_information(domain))

    elif choice == "5":
        full_scan()

    elif choice == "6":
        print("Goodbye!")
        break

    else:
        print("Invalid option.")

