# Copyright (c) 2025 Jordan Davis
# Licensed under the Apache 2.0 License. See LICENSE file in the project root for full license information.

from dotenv import load_dotenv
import os
import requests
import re

load_dotenv()
vulners_api_key = os.getenv("VULNERS_API_KEY")

CVSS_vector_pattern = re.compile( r'(CVSS:\d+\.\d+/)?AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]')

home_net = "$HOME_NET"

service_map = {
    "fortios": {"proto": "tcp", "name": "Fortios"}, #ok so this can pull multiple things service related and also port
    "apache": {"proto": "tcp", "name": "Apache"},   # going to add proto soon
    "nginx": {"proto": "tcp", "name": "Nginx"},     #need to add more services without getting false positives
    "ftp": {"port": "21", "proto": "tcp", "name": "FTP"},        #will add udp and icmp proto keys for dict soon
    "ldap": {"port": "389", "proto": "tcp", "name": "LDAP"},     
    "ssh": {"port": "22", "proto": "tcp", "name": "SSH"},         
    "smb": {"port": "445", "proto": "tcp", "name": "SMB"},
    "windows":{"name": "Windows"},


}





# Function to fetch CVE details from Vulners API
def fetch_cve_data(cve_id):
    try:
        # Correct URL with the CVE ID parameter using the apiKey variable
        url = f"https://vulners.com/api/v3/search/id/?id={cve_id}&apiKey={vulners_api_key}"


        # Make the request to Vulners
        response = requests.get(url)
        response.raise_for_status()  # Raises error if API call fails
        data = response.json()

        if data.get("result") == "OK" and "data" in data:
            documents = data["data"].get("documents", {})

            if cve_id in documents:
                doc = documents[cve_id]
                description = doc.get("description","")

                cvss_vector = None
                cvss3 = doc.get('cvss3')
                if cvss3:
                    cvss_v3 = cvss3.get('cvssV3')
                    if cvss_v3:
                        cvss_vector = cvss_v3.get('vectorString')




                if description:
                   # print(f"[DEBUG] Found JSON CVSS vector: {cvss_vector}")
                   # print(f"[DEBUG] Found description: {description[:100]}...")  # Show first 100 chars
                    return description, cvss_vector
                else:
                     print("[DEBUG] No description found in document.")
                     return f"No description found for {cve_id}"
            else:
                print(f"[DEBUG] CVE ID {cve_id} not found in documents.")      #all print statements here just for debugging they can be deleted and or removed but they will help you troubleshoot when pulling for services
                return f"No description found for {cve_id}"

        else:
             print("[DEBUG] No valid data found in API response.")
             return f"No data found for {cve_id}"

    except requests.exceptions.RequestException as e:
         print(f"Error fetching CVE data: {e}")
         return None


def extract_service(description: str, data: dict) -> list:
    pull_info = []
    desc_lower = description.lower()

    for service_name, info in data.items():
        if service_name.lower() in desc_lower:
            pull_info.append((service_name.capitalize(), info))
    if not pull_info:
        return["ANY"]
    return pull_info


def extract_cvss(description: str) -> str:
    match = CVSS_vector_pattern.search(description)
    return match.group(0) if match else "UNKNOWN"

def attack_vector_from_string(vector: str) -> str:
    if vector.startswith("CVSS:"):
        vector = vector.split('/',1)[1]

    if vector.startswith("AV:N"):
        return "NETWORK"
    elif vector.startswith("AV:P"):
        return "PHYSICAL"
    elif vector.startswith("AV:L"):
        return "LOCAL"
    elif  vector.startswith("AV:A"):
        return "ADJACENT"
    else:
        return "UNKNOWN"






async def snort(ctx, cve_id: str):
    cve_description, cvss_vector_json = fetch_cve_data(cve_id)
    if cve_description:
        affected_services = extract_service(cve_description, service_map)
        if cvss_vector_json:
            cvss_string = cvss_vector_json
            print(f"[DEBUG] Using JSON CVSS vector: {cvss_string}")             #json currently working for everything
        else:
            cvss_string = extract_cvss(cve_description)
            print(f"[DEBUG] Using regex-extracted CVSS vector: {cvss_string}")   #troubleshoot for fixing the regex which needs to be fixed to extract better data

        attack_vector = attack_vector_from_string(cvss_string)

        if affected_services == ["ANY"]:
            service_str = "ANY"
            dst_port = "ANY"
        else:
            service_str = ', '.join(item[0] for item in affected_services) 
            dst_port = "any"
            for _, service_info in services:
                port = service_info.get("port")
                if port: 
                    dst_port = port
                    break
            
        if attack_vector == "NETWORK":
            print(f"{service_str} = {service_str}")
        snort_rule = f'alert tcp any any -> {home_net} {dst_port} (msg:"Potential {cve_id} Exploit - {service_str}"; sid=1000001; rev=1;)'

        await ctx.send(
            f"Attack Vector: `{attack_vector}` (CVSS: `{cvss_string}`)\n"
            f"Generated Snort rule:\n```{snort_rule}```\nFor more details, visit: https://vulners.com/cve/{cve_id}" #need to write an elif statement so it dosent match to non network attack vectors to mitigate false positives
          )
    else:
        await ctx.send(f"No CVE data found for `{cve_id}` or failed to fetch description.")
