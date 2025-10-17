# This module is responsible for determining which STIG checklists apply to a device.

def determine_checklists(device_type, collected_data):
    """
    Analyzes a device's data to determine its profile and the single, combined checklist to use.
    """
    if device_type == 'juniper_junos':
        profile = 'juniper_switch'
        return profile, [profile]
    
    elif device_type == 'cisco_xe':
        run_all_config = collected_data.get('show run all', [])
        is_router = any(line.strip() == 'ip routing' for line in run_all_config)
        
        if is_router:
            profile = 'cisco_xe_rtr'
            return profile, [profile]
        else:
            profile = 'cisco_xe_switch'
            return profile, [profile]

    elif device_type == 'cisco_nxos':
        profile = 'cisco_nxos'
        return profile, [profile]
        
    else:
        # Return a default empty state for unsupported devices.
        return device_type, []

