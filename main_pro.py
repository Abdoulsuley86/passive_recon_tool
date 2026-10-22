#!/usr/bin/env python3
import socket
import ssl
import json
import os
import urllib.request
import urllib.error
import shutil
import subprocess
from datetime import datetime
from urllib.parse import urlparse

GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

last_report = []

def record(title, data):
    global last_report
    text = f"\n=== {title} ===\n{data}"
    print(text)
    last_report.append({
        "time": datetime.now().isoformat(timespec="seconds"),
        "title": title,
        "result": str(data)
    })

def valid_domain(domain):
    domain = domain.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).hostname or ""
    domain = domain.rstrip(".")
    if (not domain or len(domain) > 253 or
            "." not in domain or
            any(not label or len(label) > 63 or
                label.startswith("-") or label.endswith("-") or
                not all(c.isalnum() or c == "-" for c in label)
                for label in domain.split("."))):
        raise ValueError("Enter a valid domain, e.g. example.com")
    return domain

def ask_domain():
    return valid_domain(input("Enter domain: "))

def ip_information(domain):
    addresses = sorted({item[4][0] for item in
                        socket.getaddrinfo(domain, None)})
    record("IP INFORMATION", "\n".join(addresses))

def whois_information(domain):
    # Use RDAP, the modern HTTP-based registration lookup.
    url = "https://rdap.org/domain/" + domain
    request = urllib.request.Request(
        url, headers={"User-Agent": "MarmoushSentinelRecon/2.0"})
    with urllib.request.urlopen(request, timeout=12) as response:
        data = json.loads(response.read().decode("utf-8", "replace"))
    lines = [f"Domain: {data.get('ldhName', domain)}",
             f"Status: {', '.join(data.get('status', [])) or 'Not supplied'}"]
    for event in data.get("events", []):
        lines.append(f"{event.get('eventAction', 'Event')}: "
                     f"{event.get('eventDate', 'Unknown')}")
    record("DOMAIN REGISTRATION (RDAP)", "\n".join(lines))

def dns_information(domain):
    results = []
    try:
        for item in socket.getaddrinfo(domain, None):
            results.append(item[4][0])
    except socket.gaierror:
        pass
    results = sorted(set(results))
    record("DNS / ADDRESS LOOKUP",
           "\n".join(results) if results else "No addresses returned.")

def web_information(domain):
    url = "https://" + domain
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "MarmoushSentinelRecon/2.0"}
    )

    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            lines = [
                f"URL: {url}",
                f"HTTP status: {response.status}"
            ]

            for key in (
                "Server",
                "Content-Type",
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Referrer-Policy"
            ):
                value = response.headers.get(key)
                lines.append(
                    f"{key}: {value if value else 'Not returned'}"
                )

            record("WEB / SECURITY HEADERS", "\n".join(lines))

    except urllib.error.HTTPError as exc:
        lines = [f"HTTP status: {exc.code}"]
        for key in (
            "Server",
            "Content-Type",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy"
        ):
            value = exc.headers.get(key) if exc.headers else None
            lines.append(
                f"{key}: {value if value else 'Not returned'}"
            )
        record("WEB / SECURITY HEADERS", "\n".join(lines))

    except Exception as exc:
        record("WEB INFORMATION", f"Could not retrieve headers: {exc}")

def ssl_information(domain):
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as secure:
            cert = secure.getpeercert()
            lines = [
                f"Domain: {domain}",
                f"TLS version: {secure.version()}",
                f"Certificate subject: {cert.get('subject', 'Unknown')}",
                f"Issuer: {cert.get('issuer', 'Unknown')}",
                f"Valid from: {cert.get('notBefore', 'Unknown')}",
                f"Expires: {cert.get('notAfter', 'Unknown')}",
                f"Hostname verification: passed"
            ]
            record("SSL/TLS CERTIFICATE", "\n".join(lines))

def email_security(domain):
    # Uses dig if available; this performs DNS queries only.
    import shutil
    import subprocess
    if not shutil.which("dig"):
        record("EMAIL DOMAIN SECURITY",
               "Install DNS utilities to check TXT records: "
               "sudo apt install dnsutils")
        return
    findings = []
    for name in (domain, "_dmarc." + domain):
        result = subprocess.run(
            ["dig", "+short", "TXT", name],
            capture_output=True, text=True, timeout=10)
        findings.append(f"{name}:\n{result.stdout.strip() or 'No TXT record returned'}")
    record("EMAIL SECURITY (SPF / DMARC)", "\n\n".join(findings))

def save_report():
    if not last_report:
        print(YELLOW + "No results yet. Run a lookup first." + RESET)
        return
    os.makedirs("reports", exist_ok=True)
    filename = datetime.now().strftime("reports/recon_%Y%m%d_%H%M%S.json")
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(last_report, file, indent=2)
    print(GREEN + f"Report saved to {filename}" + RESET)

def show_reports():
    os.makedirs("reports", exist_ok=True)
    files = sorted(f for f in os.listdir("reports") if f.endswith(".json"))
    if not files:
        print("No saved reports yet.")
    else:
        print("\n".join(files))

def generate_pdf_report():
    """Generate a PDF from the most recently saved JSON report and open it."""
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)
    json_files = [
        os.path.join(reports_dir, name)
        for name in os.listdir(reports_dir)
        if name.lower().endswith(".json")
        and os.path.isfile(os.path.join(reports_dir, name))
    ]

    if not json_files:
        print(YELLOW + "No saved JSON reports found. Run a lookup and choose option 8 first." + RESET)
        return

    latest_json = max(json_files, key=os.path.getmtime)

    try:
        from pdf_report import generate_pdf
        generate_pdf(latest_json)
        pdf_path = os.path.join(
            reports_dir,
            os.path.splitext(os.path.basename(latest_json))[0] + ".pdf"
        )
        if os.path.isfile(pdf_path):
            opener = shutil.which("xdg-open")
            if opener:
                subprocess.Popen(
                    [opener, pdf_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                print(GREEN + f"Opening PDF: {pdf_path}" + RESET)
            else:
                print(YELLOW + "PDF created, but xdg-open is unavailable. Open this file manually: " + pdf_path + RESET)
    except ImportError as exc:
        print(RED + "PDF dependency missing. Install it with: python3 -m pip install reportlab" + RESET)
        print(RED + str(exc) + RESET)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(RED + f"PDF generation failed: {exc}" + RESET)


def main():
    while True:
        print(CYAN + """
╔══════════════════════════════════════════╗
║         MARMOUSH SENTINEL RECON          ║
║       OSINT & DOMAIN INTELLIGENCE        ║
║               Version 2.0                ║
╚══════════════════════════════════════════╝
""" + RESET)
        print("""[1] IP Address Information
[2] Domain Registration (RDAP)
[3] DNS / Address Lookup
[4] Website & Security Headers
[5] SSL/TLS Certificate Analysis
[6] Email Domain Security (SPF / DMARC)
[7] Run Basic Reconnaissance
[8] Save Report (JSON)
[9] View Saved Reports
[10] Generate PDF Report
[0] Exit""")
        choice = input("\nSelect an option: ").strip()
        if choice == "0":
            print(GREEN + "Exiting Passive Recon PRO." + RESET)
            break
        if choice == "9":
            show_reports()
            input("\nPress Enter to continue...")
            continue
        if choice == "10":
            generate_pdf_report()
            input("\\nPress Enter to continue...")
            continue
        if choice not in {str(i) for i in range(1, 11)}:
            print(RED + "Invalid menu choice." + RESET)
            continue
        if choice == "8":
            save_report()
            input("\nPress Enter to continue...")
            continue
        try:
            domain = ask_domain()
            if choice == "1":
                ip_information(domain)
            elif choice == "2":
                whois_information(domain)
            elif choice == "3":
                dns_information(domain)
            elif choice == "4":
                web_information(domain)
            elif choice == "5":
                ssl_information(domain)
            elif choice == "6":
                email_security(domain)
            elif choice == "7":
                for function in (ip_information, dns_information,
                                 web_information, ssl_information):
                    try:
                        function(domain)
                    except Exception as exc:
                        record("NOTICE", f"{function.__name__}: {exc}")
        except (ValueError, socket.gaierror, OSError,
                urllib.error.URLError, TimeoutError) as exc:
            print(RED + f"Lookup could not be completed: {exc}" + RESET)
        except Exception as exc:
            print(RED + f"Unexpected error: {exc}" + RESET)
        input("\nPress Enter to return to the menu...")

if __name__ == "__main__":
    main()
