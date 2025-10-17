# This file serves as the single source of truth for all device commands.
# It maps universal keys to platform-specific command strings.

# --- Universal Command Keys ---
# These are the keys your check files will use to access command output.
SHOW_CONFIG = 'show_config'
SHOW_CONFIG_NO_INHERIT = 'show_config_no_inherit'
SHOW_VERSION = 'show_version'
LLDP_NEIGHBORS = 'lldp_neighbors'
CHASSIS_MACS = 'chassis_macs'
INTERFACES_TERSE = 'interfaces_terse'
SPANNING_TREE = 'spanning_tree'
CDP_NEIGHBORS = 'cdp_neighbors'
SHOW_RUN_ALL = 'show_run_all'


# --- Platform-Specific Command Dictionaries ---

JUNOS_CMDS = {
    SHOW_CONFIG: 'show configuration | display set | display inheritance',
    SHOW_CONFIG_NO_INHERIT: 'show configuration | display set',
    SHOW_VERSION: 'show version',
    CHASSIS_MACS: 'show chassis mac-addresses | match "Base address"',
    LLDP_NEIGHBORS: 'show lldp neighbors | match "jmn.mil|agun.army.mil"',
    INTERFACES_TERSE: 'show interfaces terse',
    SPANNING_TREE: 'show spanning-tree interface',
}

XE_CMDS = {
    SHOW_CONFIG: 'show run',
    SHOW_RUN_ALL: 'show run all',
    SHOW_VERSION: 'show version',
    CDP_NEIGHBORS: 'show cdp neighbor detail',
    LLDP_NEIGHBORS: 'show lldp neighbor detail',
}

NXOS_CMDS = {
    SHOW_CONFIG: 'show run',
    SHOW_RUN_ALL: 'show run all',
    SHOW_VERSION: 'show version',
    CDP_NEIGHBORS: 'show cdp neighbor detail',
    LLDP_NEIGHBORS: 'show lldp neighbor detail',
}


# --- Main Map for the Data Collector ---
# This maps the device_type string from Netmiko to the appropriate command dictionary.
DEVICE_COMMAND_MAP = {
    'juniper_junos': JUNOS_CMDS,
    'cisco_xe': XE_CMDS,
    'cisco_nxos': NXOS_CMDS,
}

