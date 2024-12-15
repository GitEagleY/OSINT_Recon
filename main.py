import whois
import dns.resolver
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import shodan
from tabulate import tabulate

# Shodan API Key (Replace with your actual API key)
SHODAN_API_KEY = "your_shodan_api_key"


def get_whois_data(domain):
    """Fetch WHOIS data for the domain."""
    try:
        w = whois.whois(domain)
        return {
            "Domain": w.domain_name,
            "Registrar": w.registrar,
            "Creation Date": w.creation_date,
            "Expiration Date": w.expiration_date,
            "Name Servers": w.name_servers,
            "Organization": w.org,
            "Country": w.country,
        }
    except Exception as e:
        return {"Error": f"Failed to fetch WHOIS data: {e}"}


def get_dns_records(domain, record_type):
    """Fetch specific DNS records."""
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [answer.to_text() for answer in answers]
    except Exception as e:
        return [f"Error fetching {record_type} records: {e}"]


def get_ssl_certificate(domain):
    """Fetch SSL certificate details."""
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain,
        )
        conn.connect((domain, 443))
        cert_data = conn.getpeercert(True)
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
        return {
            "Issuer": cert.issuer.rfc4514_string(),
            "Subject": cert.subject.rfc4514_string(),
            "Valid From": cert.not_valid_before_utc,
            "Valid To": cert.not_valid_after_utc,
        }
    except Exception as e:
        return {"Error": f"Failed to fetch SSL certificate: {e}"}


def get_shodan_data(ip):
    """Fetch Shodan information about the given IP."""
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        info = api.host(ip)
        return {
            "IP": info["ip_str"],
            "Organization": info.get("org", "N/A"),
            "OS": info.get("os", "N/A"),
            "Ports": [service["port"] for service in info["data"]],
        }
    except Exception as e:
        return {"Error": f"Failed to fetch Shodan data: {e}"}


def pretty_print(data, title):
    """Print data in a readable format."""
    print(f"\n=== {title} ===")
    if isinstance(data, dict):
        table = [[key, value] for key, value in data.items()]
        print(tabulate(table, headers=["Field", "Value"], tablefmt="pretty"))
    elif isinstance(data, list):
        for item in data:
            print(f"- {item}")
    else:
        print(data)


if __name__ == "__main__":
    domain = input("Enter a domain: ")
    ip = input("Enter an IP address (leave blank to skip): ")

    # Fetch data
    whois_data = get_whois_data(domain)
    a_records = get_dns_records(domain, "A")
    mx_records = get_dns_records(domain, "MX")
    ssl_cert = get_ssl_certificate(domain)
    shodan_data = get_shodan_data(ip) if ip else None

    # Display results
    pretty_print(whois_data, "WHOIS Data")
    pretty_print(a_records, "Address Records")
    pretty_print(mx_records, "Mail Exchange Records")
    pretty_print(ssl_cert, "SSL Certificate")
    if shodan_data:
        pretty_print(shodan_data, "Shodan Data")
