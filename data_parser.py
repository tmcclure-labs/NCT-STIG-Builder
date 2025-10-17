# Import the specialist parsers
import juniper_junos_parser
import cisco_xe_parser
import cisco_nxos_parser

# This dictionary maps a device_type string to its corresponding specialist parser module.
PARSER_MAP = {
    'juniper_junos': juniper_junos_parser,
    'cisco_xe': cisco_xe_parser,
    'cisco_nxos': cisco_nxos_parser
}

def parse_device_data(device_type, collected_data):
    """
    The main controller for the data parsing layer.
    It finds the correct specialist parser based on the device type and calls it.
    """
    # Find the correct parser module from our map
    parser_module = PARSER_MAP.get(device_type)
    
    if parser_module and hasattr(parser_module, 'parse'):
        # If found, call the 'parse' function within that module
        return parser_module.parse(collected_data)
    else:
        # If no specific parser is found, log a warning and return an empty dictionary
        print(f"Warning: No data parser found for device type '{device_type}'.")
        return {}
