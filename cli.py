# Copyright (c) 2025 Jordan Davis
# Licensed under the Apache 2.0 License. See LICENSE file in the project root for full license information.

import argparse
from cve_engine import fetch_cve_data, extract_service, attack_vector_from_string, service_map

def main():
    parser = argparse.ArgumentParser(
        description="ZeroCVEs CLI - Generate Snort rules from CVE IDs with severity scoring"
    )
    parser.add_argument(
        "cve_id",
        type=str,
        help="CVE identifier (e.g., CVE-2017-0144)"
    )
    args = parser.parse_args()

    cve_id = args.cve_id.upper()
    description, cvss_vector = fetch_cve_data(cve_id)

    if not description:
        print(f"No data found for {cve_id}")
        return

    services = extract_service(description, service_map)
    attack_vector = attack_vector_from_string(cvss_vector)

    service_str = ", ".join(s[0] for s in services) if services != ["ANY"] else "ANY"

    snort_rule = f'alert tcp any any -> any any (msg:"Potential {cve_id} Exploit - {service_str}"; sid=1000001; rev=1;)'

    print(f"\nCVE: {cve_id}")
    print(f"Attack Vector: {attack_vector} (CVSS: {cvss_vector})")
    print(f"Affected Services: {service_str}")
    print(f"Generated Snort Rule:\n{snort_rule}")
    print(f"\nMore info: https://vulners.com/cve/{cve_id}\n")

if __name__ == "__main__":
    main()
