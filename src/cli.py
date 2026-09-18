import argparse
import json
from src.network import inspect_dns, inspect_tls


def main():
    parser = argparse.ArgumentParser(description="DNS & TLS Security Posture Analyzer")
    parser.add_argument("-d", "--domain", required=True, help="Target domain to inspect")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    results = {
        "domain": args.domain,
        "dns": inspect_dns(args.domain),
        "tls": inspect_tls(args.domain)
    }

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\n[+] Analysis for {args.domain}")
        print(f"    - MX Records: {len(results['dns']['MX'])} found")
        print(f"    - TLS Days to Expiry: {results['tls']['days_until_expiry']}")
        print(f"    - SAN Count: {len(results['tls']['san'])}")


if __name__ == "__main__":
    main()
