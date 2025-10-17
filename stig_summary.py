"""
This module processes completed .cklb files and generates a CSV summary of all vulnerabilities.
- Original credit: Tyler McClure
- Adapted for NCT STIG Builder
"""
import json
import os
import csv
from datetime import datetime

def _process_single_cklb(file_path):
    """
    Safely processes a single .cklb file and extracts vulnerability information.
    """
    vulnerabilities = []
    with open(file_path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
            # Safely get target data using .get() to prevent KeyErrors
            target_data = data.get('target_data', {})
            hostname = target_data.get('host_name', 'N/A')
            ip_address = target_data.get('ip_address', 'N/A')

            stig_sections = data.get('stigs', [])
            for stig in stig_sections:
                rules = stig.get('rules', [])
                for rule in rules:
                    remediation = ""
                    finding = rule.get('finding_details', '')
                    status = rule.get('status', 'not_reviewed')

                    if status == 'open':
                        remediation = rule.get('comments', '')

                    # Handle leading hyphens for better CSV compatibility
                    if remediation and remediation.startswith("-"):
                        remediation = "'" + remediation
                    if finding and finding.startswith("-"):
                        finding = "'" + finding
                    
                    vulnerability = {
                        'Hostname': hostname,
                        'IP address': ip_address,
                        'STIG ID': stig.get('stig_id', 'N/A'),
                        'Vulnerability ID': rule.get('group_id', 'N/A'),
                        'Severity': rule.get('severity', 'N/A'),
                        'Status': status,
                        'Finding': finding,
                        'Remediation': remediation
                    }
                    vulnerabilities.append(vulnerability)

        except (json.JSONDecodeError, KeyError) as e:
            print(f"Error processing {os.path.basename(file_path)}: {e}")

    return vulnerabilities

def generate_summary(directory_path, log_callback):
    """
    Generates a CSV summary from all .cklb files in a given directory.
    """
    log_callback("--- Starting STIG Summary Generation ---")
    
    now = datetime.now()
    # --- FIX: Ensure the timestamp includes hours, minutes, and seconds ---
    summary_filename = now.strftime(f"STIG_Summary_%Y%m%d_%H%M%S.csv")
    output_file_path = os.path.join(directory_path, summary_filename)
    
    fieldnames = ['Hostname', 'IP address', 'STIG ID', 'Vulnerability ID', 'Severity', 'Status', 'Finding', 'Remediation']

    all_vulnerabilities = []
    
    cklb_files_found = False
    for filename in os.listdir(directory_path):
        if filename.endswith('.cklb'):
            cklb_files_found = True
            log_callback(f"  -> Processing file: {filename}")
            file_path = os.path.join(directory_path, filename)
            vulnerabilities = _process_single_cklb(file_path)
            all_vulnerabilities.extend(vulnerabilities)

    if not cklb_files_found:
        log_callback("No .cklb files found in the selected directory.")
        log_callback("--- Summary Generation Aborted ---")
        return

    try:
        with open(output_file_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_vulnerabilities)
        
        log_callback(f"\nSuccessfully created summary file: {summary_filename}")
        log_callback(f"Saved to: {directory_path}")
    except Exception as e:
        log_callback(f"ERROR: Could not write summary file. Reason: {e}")

    log_callback("\n--- STIG Summary Generation Complete ---")

