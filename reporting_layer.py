import os
import json
from datetime import datetime
import re

def generate_reports(all_analysis_results, all_devices_data, output_path, log_callback, username):
    """
    Generates STIG checklist files based on the analysis results, with enriched asset data and a new naming convention.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))

    for ip, analysis_data in all_analysis_results.items():
        device_profile = analysis_data.get('device_profile')
        results = analysis_data.get('results')
        parsed_data = analysis_data.get('parsed_data', {})

        if not device_profile:
            log_callback(f"  -> Skipping report for {ip}, no device profile found.")
            continue

        log_callback(f"Generating report for {ip} ({device_profile})...")
        
        hostname = parsed_data.get('hostname', 'unknown')
        
        template_filename = f"{device_profile}.cklb"
        template_path = os.path.join(script_dir, 'libraries', device_profile, template_filename)
        
        log_callback(f"  -> Looking for template at: {template_path}")

        data = None
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except FileNotFoundError:
            log_callback(f"  -> ERROR: Checklist template not found for '{device_profile}'.")
            continue
        except json.JSONDecodeError:
            log_callback(f"  -> ERROR: Template file '{template_filename}' is not valid JSON.")
            continue
        except Exception as e:
            log_callback(f"  -> ERROR: Could not read template file for {ip}: {e}")
            continue

        # --- Extract STIG metadata for filename ---
        version = "N/A"
        release = "N/A"
        release_date = "NODATE"
        if data and "stigs" in data and data["stigs"]:
            first_stig = data["stigs"][0]
            version = first_stig.get("version", "N/A")
            release_info = first_stig.get("release_info", "")
            
            release_match = re.search(r"Release: (\d+)", release_info)
            if release_match:
                release = release_match.group(1)

            date_match = re.search(r"Benchmark Date: (\d{2} \w{3} \d{4})", release_info)
            if date_match:
                try:
                    date_obj = datetime.strptime(date_match.group(1), "%d %b %Y")
                    release_date = date_obj.strftime("%Y%m%d")
                except ValueError:
                    pass

        # --- Iterate through all STIG sections in the checklist ---
        if data and "stigs" in data and isinstance(data["stigs"], list):
            for stig_section in data["stigs"]:
                rules = stig_section.get("rules", [])
                
                if not results:
                    log_callback(f"  -> WARNING: No analysis results found for {ip} to populate STIG section '{stig_section.get('stig_id', 'Unknown')}'.")
                    continue
                
                for rule in rules:
                    vuln_id_from_ckl = rule.get('group_id')
                    matching_result = next((res for res in results if res.get('vuln_id') == vuln_id_from_ckl), None)

                    if matching_result:
                        status_map = {
                            'not_a_finding': 'not_a_finding', 'open': 'open',
                            'not_applicable': 'not_applicable', 'not_reviewed': 'not_reviewed'
                        }
                        rule['status'] = status_map.get(matching_result.get('status'), 'not_reviewed')
                        rule['comments'] = matching_result.get('comments', '')
                        rule['finding_details'] = matching_result.get('finding_details', '')
        
        # --- Populate the 'target_data' section ---
        if "target_data" in data:
            domain_name = parsed_data.get('domain_name', 'localdomain')
            chassis_macs = parsed_data.get('chassis_macs', [])
            
            data["target_data"]["host_name"] = hostname
            data["target_data"]["ip_address"] = parsed_data.get('management_ip', ip)
            data["target_data"]["fqdn"] = f"{hostname}.{domain_name}"
            data["target_data"]["mac_address"] = chassis_macs[0] if chassis_macs else "N/A"
            data["target_data"]["role"] = parsed_data.get('switch_role', 'None')
            data["target_data"]["technology_area"] = "Internal Network"
            data["target_data"]["comments"] = f"Created by NCT user {username}"

        # --- Construct the updated filename ---
        output_filename = f"{hostname}_JUNIPER_EX_V{version}R{release}_COMBO_{release_date}.cklb"
        output_filepath = os.path.join(output_path, output_filename)

        try:
            with open(output_filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
            log_callback(f"  -> Successfully created checklist: {output_filename}")
        except Exception as e:
            log_callback(f"  -> ERROR: Failed to write checklist for {ip}: {e}")

