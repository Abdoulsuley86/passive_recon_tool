#!/usr/bin/env python3

import socket
import subprocess
import urllib.parse
import urllib.request
import json


# ============================================================
# IP INFORMATION
# ============================================================

def ip_information(domain):
    try:
        ip = socket.gethostbyname(domain)

        return (
            "\n[IP INFORMATION]\n"
            + "=" * 50 + "\n"
            + f"Domain: {domain}\n"
            + f"IP Address: {ip}\n"
        )

    except socket.gaierror:
        return (
            "\n[IP INFORMATION]\n"
            + "=" * 50 + "\n"
            + "Could not resolve domain to an IP address.\n"
        )

    except Exception as e:
        return (
            "\n[IP INFORMATION]\n"
            + "=" * 50 + "\n"
            + f"IP lookup failed: {e}\n"
        )


# ============================================================
# WHOIS INFORMATION
# RDAP IS NOT USED
# ============================================================

def whois_information(domain):
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=30
        )

        output = result.stdout.strip()

        if not output:
            output = result.stderr.strip()

        if output:
            return (
                "\n[WHOIS INFORMATION]\n"
                + "=" * 50 + "\n"
                + output
                + "\n"
            )

        return (
            "\n[WHOIS INFORMATION]\n"
            + "=" * 50 + "\n"
            + "No WHOIS information returned.\n"
        )

    except FileNotFoundError:
        return (
            "\n[WHOIS INFORMATION]\n"
            + "=" * 50 + "\n"
            + "WHOIS is not installed.\n"
            + "Install it with: sudo apt install whois\n"
        )

    except subprocess.TimeoutExpired:
        return (
            "\n[WHOIS INFORMATION]\n"
            + "=" * 50 + "\n"
            + "WHOIS request timed out.\n"
        )

    except Exception as e:
        return (
            "\n[WHOIS INFORMATION]\n"
            + "=" * 50 + "\n"
            + f"WHOIS lookup failed: {e}\n"
        )


# ============================================================
# DNS INFORMATION
# ============================================================

def dns_information(domain):
    try:
        addresses = socket.getaddrinfo(domain, None)

        ips = sorted(
            set(
                address[4][0]
                for address in addresses
                if address[4]
            )
        )

        output = (
            "\n[DNS INFORMATION]\n"
            + "=" * 50 + "\n"
            + f"Domain: {domain}\n"
        )

        if ips:
            output += "Resolved addresses:\n"
            for ip in ips:
                output += f"  - {ip}\n"
        else:
            output += "No DNS addresses found.\n"

        return output

    except Exception as e:
        return (
            "\n[DNS INFORMATION]\n"
            + "=" * 50 + "\n"
            + f"DNS lookup failed: {e}\n"
        )


# ============================================================
# WEB INFORMATION
# ============================================================

def web_information(domain):
    try:
        if not domain.startswith(("http://", "https://")):
            url = "https://" + domain
        else:
            url = domain

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Passive-Recon-Tool/1.0"
            }
        )

        with urllib.request.urlopen(request, timeout=15) as response:
            final_url = response.geturl()
            status = response.status
            server = response.headers.get("Server", "Not disclosed")
            content_type = response.headers.get(
                "Content-Type",
                "Not disclosed"
            )

        return (
            "\n[WEB INFORMATION]\n"
            + "=" * 50 + "\n"
            + f"URL: {url}\n"
            + f"Final URL: {final_url}\n"
            + f"HTTP Status: {status}\n"
            + f"Server: {server}\n"
            + f"Content-Type: {content_type}\n"
        )

    except urllib.error.HTTPError as e:
        return (
            "\n[WEB INFORMATION]\n"
            + "=" * 50 + "\n"
            + f"HTTP Error: {e.code}\n"
        )

    except urllib.error.URLError as e:
        return (
            "\n[WEB INFORMATION]\n"
            + "=" * 50 + "\n"
            + f"Could not connect to website: {e.reason}\n"
        )

    except Exception as e:
        return (
            "\n[WEB INFORMATION]\n"
            + "=" * 50 + "\n"
            + f"Web lookup failed: {e}\n"
        )


# ============================================================
# FULL PASSIVE SCAN
# ============================================================

def full_passive_scan(domain):
    output = "\n"
    output += "=" * 60 + "\n"
    output += "FULL PASSIVE SCAN\n"
    output += "=" * 60 + "\n"

    output += ip_information(domain)
    output += whois_information(domain)
    output += dns_information(domain)
    output += web_information(domain)

    return output


# ============================================================
# MAIN MENU
# ============================================================

def main():
    while True:
        print("\nPASSIVE RECON TOOL")
        print("=" * 30)
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
            domain = input("Enter domain: ").strip()
            print(full_passive_scan(domain))

        elif choice == "6":
            print("Exiting Passive Recon Tool...")
            break

        else:
            print("Invalid option. Please choose 1-6.")


if __name__ == "__main__":
    main()


