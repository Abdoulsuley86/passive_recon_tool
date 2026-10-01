def whois_information(domain):
    try:
        import json
        import urllib.request
        import urllib.error

        url = f"https://rdap.org/domain/{domain}"

        request = urllib.request.Request(
            url,
            headers={"User-Agent": "Passive-Recon-Tool/1.0"}
        )

        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))

        output = "\n[WHOIS / RDAP INFORMATION]\n"
        output += "=" * 40 + "\n"

        output += f"Domain: {data.get('ldhName', domain)}\n"
        output += f"Status: {', '.join(data.get('status', []))}\n"

        events = data.get("events", [])

        for event in events:
            event_type = event.get("eventAction")
            event_date = event.get("eventDate")

            if event_type and event_date:
                output += f"{event_type}: {event_date}\n"

        return output

    except urllib.error.HTTPError as e:
        return f"\n[WHOIS / RDAP INFORMATION]\nRDAP request failed: HTTP {e.code}\n"

    except urllib.error.URLError:
        return "\n[WHOIS / RDAP INFORMATION]\nCould not connect to RDAP service.\n"

    except Exception as e:
        return f"\n[WHOIS / RDAP INFORMATION]\nRDAP lookup failed: {e}\n"

