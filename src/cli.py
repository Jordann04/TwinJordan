# Copyright (c) 2025 Jordan Davis
# Licensed under the Apache 2.0 License. See LICENSE file in the project root for full license information.

import argparse
from cve_engine import fetch_cve_data, extract_service, attack_vector_from_string, service_map

home_net = "$HOME_NET"   #please make sure you map your home net on your snort config

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

    if services == "ANY":
        service_str = "ANY"
        dst_port = "any"

    else:
        service_str = ", ".join(s[0] for s in services)
        dst_port = "any"
        for _, service_info in services:
            port = service_info.get("port")
            if port:
                dst_port = port
                break
         
    
    

    snort_rule = f'alert tcp any any -> {home_net} {dst_port} (msg:"Potential {cve_id} Exploit - {service_str}"; sid=1000001; rev=1;)'  #going to use random radiant to pull diffrent sid and revs soon 

    print(f"\nCVE: {cve_id}")
    print(f"Attack Vector: {attack_vector} (CVSS: {cvss_vector})")
    print(f"Affected Services: {service_str}")
    print(f"Generated Snort Rule:\n{snort_rule}")
    print(f"\nMore info: https://vulners.com/cve/{cve_id}\n")

if __name__ == "__main__":
    main()
