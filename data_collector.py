import concurrent.futures
from netmiko import ConnectHandler
# Corrected import for modern Netmiko versions
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from netmiko.ssh_autodetect import SSHDetect

# Import our new command map
import command_map

def _collect_single_device_data(ip, username, password, log_callback):
    """
    Connects to a single device, detects its type, runs commands, and returns the data.
    """
    log_callback(f"Connecting to {ip}...")

    # --- Step 1: Autodetect device type ---
    autodetect_info = {
        'device_type': 'autodetect',
        'host': ip,
        'username': username,
        'password': password,
    }
    
    device_type = None
    try:
        guesser = SSHDetect(**autodetect_info, banner_timeout=60)
        best_match = guesser.autodetect()
        if best_match:
            device_type = best_match
            log_callback(f"  -> {ip}: Detected device type: {device_type}")
        else:
            log_callback(f"  -> {ip}: Could not determine device type.")
            return ip, None
    except (NetmikoAuthenticationException, NetmikoTimeoutException) as e:
        log_callback(f"  -> {ip}: Failed to connect for autodetect: {e}")
        return ip, None

    # --- Step 2: If supported, get the command dictionary from our map ---
    commands_to_run_dict = command_map.DEVICE_COMMAND_MAP.get(device_type)
    if not commands_to_run_dict:
        log_callback(f"  -> {ip}: Device type '{device_type}' is not supported for data collection.")
        return ip, None

    device_info = {
        'device_type': device_type,
        'host': ip,
        'username': username,
        'password': password,
    }

    collected_data = {}
    try:
        with ConnectHandler(**device_info) as net_connect:
            # For Cisco devices that need terminal length set at the start of the session
            if device_type in ['cisco_xe', 'cisco_nxos']:
                net_connect.send_command('terminal length 0', expect_string=r'#')

            # --- UPDATED: Loop through the dictionary from the command map ---
            for universal_key, command_string in commands_to_run_dict.items():
                log_callback(f"  -> {ip}: Running command for key: '{universal_key}'")
                output = net_connect.send_command(command_string, read_timeout=120)
                
                # --- UPDATED: Store output using the universal key ---
                collected_data[universal_key] = output.splitlines() if output else []
        
        log_callback(f"  -> {ip}: Data collection successful.")
        return ip, {'device_type': device_type, 'collected_data': collected_data}

    except (NetmikoAuthenticationException, NetmikoTimeoutException, Exception) as e:
        log_callback(f"  -> {ip}: Failed during command execution: {e}")
        return ip, None

def collect_all_device_data(device_ips, username, password, log_callback):
    """
    Uses a thread pool to run data collection on all devices concurrently.
    """
    all_devices_data = {}
    log_callback("--- Starting Data Collection ---\n")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_ip = {executor.submit(_collect_single_device_data, ip, username, password, log_callback): ip for ip in device_ips}
        
        for future in concurrent.futures.as_completed(future_to_ip):
            ip, result = future.result()
            if result:
                all_devices_data[ip] = result

    log_callback("\n--- Data Collection Complete ---\n")
    return all_devices_data

