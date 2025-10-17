import os
import importlib.util
import checklist_determinator
import data_parser

def analyze_all_devices(all_devices_data, log_callback): # <-- Added log_callback
    """
    Analyzes the collected data for all devices and returns the results.
    """
    all_results = {}
    
    script_dir = os.path.dirname(os.path.abspath(__file__))

    for ip, device_data in all_devices_data.items():
        device_type = device_data.get('device_type')
        collected_data = device_data.get('collected_data')
        
        if not device_type or not collected_data:
            log_callback(f"Skipping {ip} due to missing data.")
            continue

        parsed_data = data_parser.parse_device_data(device_type, collected_data)
        device_profile, checklists = checklist_determinator.determine_checklists(device_type, collected_data)
        
        if not device_profile:
            log_callback(f"Could not determine profile for {ip} ({device_type}). Skipping analysis.")
            continue

        log_callback(f"Analyzing {ip} with profile '{device_profile}'...")
        device_results = []
        vuln_dir = os.path.join(script_dir, 'vulns', device_profile)

        if not os.path.isdir(vuln_dir):
            log_callback(f"Warning: Vulnerability directory not found for profile '{device_profile}' at '{vuln_dir}'")
            continue

        for filename in os.listdir(vuln_dir):
            if filename.endswith('.py') and filename.startswith('V-'):
                module_name = filename[:-3]
                file_path = os.path.join(vuln_dir, filename)
                
                try:
                    spec = importlib.util.spec_from_file_location(module_name, file_path)
                    vuln_module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(vuln_module)
                    
                    if hasattr(vuln_module, 'check'):
                        result = vuln_module.check(collected_data, parsed_data)
                        result['vuln_id'] = module_name
                        device_results.append(result)
                except Exception as e:
                    log_callback(f"Error executing check '{filename}' for {ip}: {e}")

        all_results[ip] = {
            'device_profile': device_profile,
            'results': device_results,
            'parsed_data': parsed_data # <-- NEW: Pass parsed data to the next layer
        }
        log_callback(f"Analysis complete for {ip}. Found {len(device_results)} results.")

    return all_results

