import re
import command_map

def _get_hostname(config_lines):
    """Extracts the hostname from the configuration."""
    for line in config_lines:
        if line.startswith('set system host-name'):
            return line.split()[-1]
    return 'unknown-host'

def _get_switch_role(config_lines):
    """Extracts the hostname from the configuration and uses that to determine switch role"""
    for line in config_lines:
        if line.startswith('set system host-name'):
            hostname = line.split()[-1]
            if len(hostname.split("-")) > 1:
                switch_identifier = hostname.split("-")[1]
                if switch_identifier.startswith('a'):
                    return 'access'
    return 'not an access switch'

def _get_os_version(version_output):
    """Parses the 'show version' output to find the Junos OS version."""
    for line in version_output:
        if "Junos:" in line:
            return line.split(":")[-1].strip()
    return 'unknown-version'

def _get_switch_model(version_output):
    """Parses the 'show version' output to find the device model."""
    for line in version_output:
        if "Model:" in line:
            return line.split(":")[-1].strip()
    return 'unknown-model'

def _get_chassis_mac(chassis_mac_output):
    """Parses the 'show chassis mac-addresses' output."""
    chassis_macs = []
    for line in chassis_mac_output:
        if 'Base address' in line and len(line.split()) > 2:
            chassis_macs.append(line.split()[-1])
    return chassis_macs

def _get_ntp_servers(config_lines):
    """Extracts a list of configured NTP server IPs."""
    ntp_servers = set()
    for line in config_lines:
        if "set system ntp server" in line:
            ntp_servers.add(line.split()[4])
    return list(ntp_servers)

def _get_ntp_keys(config_lines):
    """Extracts a list of configured NTP authentication keys."""
    ntp_keys = set()
    for line in config_lines:
        if "set system ntp authentication-key" in line:
            ntp_keys.add(line.split()[4])
    return list(ntp_keys)

def _get_syslog_servers(config_lines):
    """Extracts a list of configured syslog server IPs."""
    syslog_servers = set()
    for line in config_lines:
        if line.startswith("set system syslog host"):
            syslog_servers.add(line.split()[4])
    return list(syslog_servers)

def _get_syslog_files(config_lines):
    """Extracts a list of configured local syslog files."""
    syslog_files = set()
    for line in config_lines:
        if line.startswith("set system syslog file"):
            syslog_files.add(line.split()[4])
    return list(syslog_files)

def _get_radius_servers(config_lines, dot1x_auth_profiles):
    """Extracts a list of configured RADIUS server IPs based on auth profiles."""
    radius_servers = set()
    for line in config_lines:
        for auth_prof in dot1x_auth_profiles:
            if f"set access profile {auth_prof} radius-server" in line:
                radius_servers.add(line.split()[5])
    return list(radius_servers)

def _get_tacacs_servers(config_lines):
    """Extracts a list of configured TACACS+ server IPs."""
    tacacs_servers = set()
    for line in config_lines:
        if line.startswith("set system tacplus-server"):
            tacacs_servers.add(line.split()[3])
    return list(tacacs_servers)

def _get_trunk_ports(config_lines):
    """Extracts a list of all trunk ports."""
    trunk_ports = set()
    for line in config_lines:
        if 'interface-mode trunk' in line:
            trunk_ports.add(line.split()[2])
    return list(trunk_ports)

def _get_access_ports(config_lines):
    """Extracts a list of all access ports."""
    access_ports = set()
    for line in config_lines:
        if 'family ethernet-switching interface-mode access' in line:
            access_ports.add(line.split()[2])
    return list(access_ports)

def _get_all_ports(config_lines):
    """Extracts all physical and logical interface names."""
    all_ports = set()
    interface_pattern = re.compile(r"set interfaces (ge-|xe-|ae-)\S+")
    for line in config_lines:
        if interface_pattern.match(line):
            all_ports.add(line.split()[2])
    return list(all_ports)

def _get_all_irb_ids(config_lines):
    """Extracts all configured IRB unit IDs."""
    all_irb_ids = set()
    for line in config_lines:
        if line.startswith("set interfaces irb unit"):
            all_irb_ids.add(line.split()[4])
    return list(all_irb_ids)

def _get_mgmt_irb_id(config_lines):
    """Finds the IRB unit ID associated with the TACACS+ source-address."""
    mgmt_ip = None
    for line in config_lines:
        if "set system tacplus-server" in line and "source-address" in line:
            mgmt_ip = line.split()[-1]
            break
    if mgmt_ip:
        for line in config_lines:
            if f"family inet address {mgmt_ip}" in line:
                return line.split()[4]
    return 'unknown'

def _get_root_ports(span_output):
    """Extracts a list of spanning-tree ROOT ports."""
    root_ports = set()
    for line in span_output:
        parts = line.split()
        if parts and "ROOT" in parts:
            root_ports.add(parts[0])
    return list(root_ports)

def _get_alt_ports(span_output):
    """Extracts a list of spanning-tree ALT ports."""
    alt_ports = set()
    for line in span_output:
        parts = line.split()
        if parts and "ALT" in parts:
            alt_ports.add(parts[0])
    return list(alt_ports)

def _get_user_profiles(config_lines):
    """Extracts a list of configured local user accounts."""
    user_profiles = set()
    for line in config_lines:
        if line.startswith("set system login user"):
            user_profiles.add(line.split()[4])
    return list(user_profiles)

def _get_user_classes(config_lines):
    """Extracts a list of configured user classes."""
    login_classes = set()
    for line in config_lines:
        if line.startswith("set system login class"):
            login_classes.add(line.split()[4])
    return list(login_classes)

def _get_management_ip(config_lines):
    """Extracts the first TACACS+ source-address found."""
    for line in config_lines:
        if "set system tacplus-server" in line and "source-address" in line:
            return line.split()[-1]
    return 'unknown'

def _get_lldp_neighbor_ints(lldp_lines):
    """Parses simple 'show lldp neighbors' output to get a list of interfaces."""
    lldp_neighbor_interfaces = set()
    for line in lldp_lines:
        try:
            parts = line.split()
            if len(parts) > 1:
                if parts[1] == '-':
                    lldp_neighbor_interfaces.add(parts[0])
                elif parts[1].startswith('ae'):
                    lldp_neighbor_interfaces.add(parts[1])
        except IndexError:
            continue
    return list(lldp_neighbor_interfaces)

def _get_control_plane_acl(config_lines):
    """Extracts all lines related to the control-plane-acl firewall filter."""
    control_plane_acl = set()
    for line in config_lines:
        if line.startswith("set firewall family inet filter control-plane-acl term"):
            control_plane_acl.add(line)
    return list(control_plane_acl)

def _get_firewall_policers(config_lines):
    """Extracts all configured firewall policer lines."""
    firewall_policers = set()
    for line in config_lines:
        if line.startswith("set firewall policer"):
            firewall_policers.add(line)
    return list(firewall_policers)

def _get_up_interfaces(terse_output):
    """Parses 'show interfaces terse' to find interfaces that are up/up."""
    up_interfaces = set()
    for line in terse_output:
        if "down" not in line and ".0" not in line:
            if line.startswith("ae") or line.startswith("xe") or line.startswith("ge"):
                up_interfaces.add(line.split()[0])
    return list(up_interfaces)

def _get_native_vlans(config_lines):
    """Extracts a dictionary of interfaces and their configured native VLAN ID."""
    native_vlans = {}
    for line in config_lines:
        if "native-vlan-id" in line:
            vlan_id = line.split()[-1]
            interface = line.split()[2]
            native_vlans[interface] = vlan_id
    return native_vlans

def _get_domain_name(config_lines):
    """Extracts the system domain name."""
    for line in config_lines:
        if "set system domain-name" in line:
            return line.split()[-1]
    return 'unknown'

def _get_dot1x_auth_profile(config_lines):
    """Extracts a list of 802.1x authentication profile names."""
    dot1x_auth_profiles = set()
    for line in config_lines:
        if "set protocols dot1x authenticator authentication-profile-name" in line:
            dot1x_auth_profiles.add(line.split()[-1])
    return list(dot1x_auth_profiles)

def _get_snmp_users(config_lines):
    """
    Parses the configuration to create a dictionary of SNMPv3 users
    and their configured authentication and privacy algorithms.
    Example: {'solarwinds': {'auth_type': 'sha', 'priv_type': 'aes128'}}
    """
    snmp_users = {}
    for line in config_lines:
        if "set snmp v3 usm local-engine user" in line:
            parts = line.split()
            if len(parts) > 7:
                username = parts[6]
                snmp_users.setdefault(username, {})
                
                config_type = parts[7]
                if config_type.startswith("authentication-"):
                    auth_algorithm = config_type.split('-', 1)[1]
                    snmp_users[username]['auth_type'] = auth_algorithm
                elif config_type.startswith("privacy-"):
                    priv_algorithm = config_type.split('-', 1)[1]
                    snmp_users[username]['priv_type'] = priv_algorithm
    return snmp_users

def _get_storm_profiles(config_lines):
    storm_profiles = set()
    for line in config_lines:
        if "set forwarding-options storm-control-profiles" in line:
            storm_profiles.add(line.split()[3])
    return list(storm_profiles)

def parse(collected_data):
    """
    The main parsing function for Juniper Junos devices.
    It takes raw command output and returns a structured dictionary of parsed data.
    """
    config_lines = collected_data.get(command_map.SHOW_CONFIG, [])
    lldp_lines = collected_data.get(command_map.LLDP_NEIGHBORS, [])
    version_output = collected_data.get(command_map.SHOW_VERSION, [])
    chassis_mac_output = collected_data.get(command_map.CHASSIS_MACS, [])
    span_output = collected_data.get(command_map.SPANNING_TREE, [])
    terse_output = collected_data.get(command_map.INTERFACES_TERSE, [])
    
    # --- Call functions in the correct order to pass data ---
    dot1x_auth_profiles = _get_dot1x_auth_profile(config_lines)
    radius_servers = _get_radius_servers(config_lines, dot1x_auth_profiles)

    parsed_data = {
        'hostname': _get_hostname(config_lines),
        'switch_role': _get_switch_role(config_lines),
        'os_version': _get_os_version(version_output),
        'model': _get_switch_model(version_output),
        'chassis_macs': _get_chassis_mac(chassis_mac_output),
        'ntp_servers': _get_ntp_servers(config_lines),
        'ntp_keys': _get_ntp_keys(config_lines),
        'syslog_servers': _get_syslog_servers(config_lines),
        'syslog_files': _get_syslog_files(config_lines),
        'radius_servers': radius_servers, # Use the result from our ordered call
        'tacacs_servers': _get_tacacs_servers(config_lines),
        'trunk_ports': _get_trunk_ports(config_lines),
        'access_ports': _get_access_ports(config_lines),
        'all_ports': _get_all_ports(config_lines),
        'all_irb_ids': _get_all_irb_ids(config_lines),
        'mgmt_irb_id': _get_mgmt_irb_id(config_lines),
        'root_ports': _get_root_ports(span_output),
        'alt_ports': _get_alt_ports(span_output),
        'user_profiles': _get_user_profiles(config_lines),
        'user_classes': _get_user_classes(config_lines),
        'management_ip': _get_management_ip(config_lines),
        'lldp_neighbors': _get_lldp_neighbor_ints(lldp_lines),
        'control_plane_acl': _get_control_plane_acl(config_lines),
        'firewall_policers': _get_firewall_policers(config_lines),
        'up_interfaces': _get_up_interfaces(terse_output),
        'native_vlans': _get_native_vlans(config_lines),
        'domain_name': _get_domain_name(config_lines),
        'dot1x_auth_profiles': dot1x_auth_profiles,
        'snmp_users': _get_snmp_users(config_lines),
        'storm_profiles': _get_storm_profiles(config_lines)
    }
    return parsed_data

