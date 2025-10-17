# Network-Configuration-Tool-STIG-Builder

# 1. Overview

The NCT STIG Builder is a Python-based graphical user interface (GUI) tool designed to automate the process of creating DISA STIG (Security Technical Implementation Guide) checklists for network devices. It securely connects to devices, gathers configuration and operational data, analyzes this data against a library of vulnerability checks, and generates completed STIG .cklb files that can be opened in STIG Viewer.

The tool is built with a modular, multi-layered architecture to ensure it is maintainable, scalable, and easy to extend with new checks or device types.

# 2. Core Features

* Automated Data Collection: Securely connects to multiple devices concurrently using SSH, auto-detects the device type (e.g., Juniper Junos, Cisco XE, Cisco NXOS), and runs a predefined set of commands to gather necessary data.

* Modular Analysis Engine: Uses a flexible, file-based system for vulnerability checks. Each STIG rule is a separate .py file, making it easy to add, update, or remove individual checks without modifying the core application.

* Intelligent Data Parsing: A dedicated data enrichment layer pre-processes raw command output into a structured, easy-to-use format. This simplifies the logic within vulnerability checks by providing clean data points like lists of trunk ports, access ports, LLDP neighbors, and more.

* Automated Checklist Generation: Parses official STIG .cklb templates and programmatically updates the status (not_a_finding, open, etc.), comments, and finding details for each vulnerability based on the analysis results.

* Comprehensive Reporting: Automatically generates a timestamped folder for each run, containing the completed .cklb file for each device and a consolidated CSV summary report of all findings.

* User-Friendly GUI: Provides a simple graphical interface for entering credentials, selecting device lists, and monitoring the progress of a job.

# 3. Project Structure & Workflow

The application is designed as a data pipeline, with each Python file serving a specific role.

**main.py** - The GUI Controller & Orchestrator

  * Role: The user's entry point and the master controller.

  * Function: Displays the GUI, gathers inputs, and orchestrates the entire process by calling the other modules in sequence.

**data_collector.py** - The Data Collection Layer ("The Librarian")

  * Role: The networking engine.

  * Function: Connects to devices, runs commands defined in command_map.py, and gathers all raw output.

**data_parser.py** - The Data Enrichment Layer ("The Controller")

  * Role: The main controller for data pre-processing.

  * Function: Looks at the device type and delegates the parsing work to the correct specialist parser (e.g., juniper_junos_parser.py).

**juniper_junos_parser.py** | **cisco_xe_parser.py** | **cisco_nxos_parser.py** - Specialist Parsers

  * Role: Experts on a single device platform.

  * Function: Transform raw command output into a clean, structured parsed_data dictionary.

**checklist_determinator.py** - The High-Level Analyst

  * Role: The first stage of analysis.

  * Function: Determines the device's specific role (e.g., cisco_xe_switch vs. cisco_xe_rtr) to decide which set of vulnerability checks to run.

**stig_analyzer.py** - The Analysis Engine ("The Head Researcher")

* Role: The core of the analysis layer.

* Function: Uses the device profile to find the correct vulns sub-directory, then dynamically loads and executes every V-XXXXXX.py file within it, passing the collected and parsed data to each one.

**The V-XXXXXX.py Files** - The Vulnerability Checks ("The Research Assistants")

* Role: Self-contained scripts for checking a single STIG rule.

* Function: Contain the specific logic to determine if a vulnerability is a finding, not a finding, or not applicable.

**reporting_layer.py** - The Reporting Layer ("The Scribe")

* Role: The final stage of the process.

* Function: Takes the final analysis results, finds the correct .cklb template from the libraries folder, and writes the status, comments, and finding details for each vulnerability into a new, completed checklist file.

**stig_summary.py** - The Summary Generator

* Role: The post-processing report generator.

* Function: Called automatically at the end of a run. It scans the newly created .cklb files and generates a single CSV file summarizing all findings across all processed devices.

# 4. Setup & Configuration

For the tool to function correctly, a specific directory structure must be in place.

**4.1 Required Directory and File Structure**

All the core .py scripts must reside in the same root project folder. This folder must also contain the following subdirectories with the exact names specified:

libraries/: This directory holds the STIG checklist templates. It must contain subdirectories for each device profile.

libraries/junos_switch/

libraries/cisco_xe_rtr/

libraries/cisco_xe_switch/

libraries/cisco_nxos/

**Example Template Path: libraries/junos_switch/junos_switch.cklb**

vulns/: This directory holds all the individual vulnerability check files. It must also contain subdirectories for each device profile.

vulns/junos_switch/

vulns/cisco_xe_rtr/

vulns/cisco_xe_switch/

vulns/cisco_nxos/

Example Check File Path: vulns/junos_switch/V-253878.py

**Required Python Files in the Root Folder:**

main.py

data_collector.py

data_parser.py

juniper_junos_parser.py

cisco_xe_parser.py

cisco_nxos_parser.py

checklist_determinator.py

stig_analyzer.py

reporting_layer.py

stig_summary.py

command_map.py

**4.2 Configuration File (nct_stig.ini)**

To avoid prompting for the output location every time, the tool uses a configuration file.

First Run: The first time you run main.py, it will prompt you to select a base directory where you want your "STIG Reports" folder to be created.

File Creation: After you select a folder, the script automatically creates a configuration file at:

Windows: %APPDATA%\NCT_STIG_Builder\nct_stig.ini

macOS/Linux: ~/.config/NCT_STIG_Builder/nct_stig.ini (or a similar user configuration directory)

Purpose: This .ini file stores the path to your "STIG Reports" directory. On subsequent runs, the tool will read this file and automatically use the saved path, creating new timestamped subfolders inside it for each job. This feature is key if the tool will be stored on your organizations SharePoint, and linked to each individual filesystem via their OneDrive. If you need to change the output location, you can delete this .ini file, and the application will prompt you to select a new directory on its next launch.

# 5. How to Use

Run the main.py script.

Enter your username and password for the network devices.

Click "Load Device IPs File" and select a .txt file containing the IP addresses of the devices you want to scan.

Click "Build STIG Checklist" to begin the process.

Monitor the log window for progress.

Once the process is complete, the output folder containing the checklists and summary CSV will open automatically.

# 6. Useful Tools

**Generate V-XXXXXX.py files in mass:**

Use the build_blank_vulns.py tool to generate new V-XXXXXX.py files.

* Create a template '.py' file. The script will copy the contents of this file and paste them in each V-XXXXXX.py file it creates

* Ensure the .cklb file that you plan to use for checklist generation has been created. This file should be stored in the correct folder in \libraries

* The script will search through the selected .cklb file to gather all of the group-IDs (vuln IDs) and utilize this data to generate the V-XXXXXX.py files

* Run build_blank_vulns.py

* "Select CKLB File" - Select the unpopulated STIG checklist .cklb file from the \libraries folder

* "Select Output Directory" - Select the folder in \vulns where you would like the V-XXXXXX.py files sent to. If you select a folder with V-XXXXXX.py files they will be overwritten.

* "Select Template File" - Select the file that contains the contents that you would like pasted into every V-XXXXXX.py file that is created.

* Open the new file and add your logic.

* For simple checks, populate the required_lines, forbidden_lines, or regex lists.

* For complex checks, uncomment and implement the perform_custom_check function, using the parsed_data dictionary to access pre-processed information.

**Modify already created .cklb files in mass:**

* Utilize stig_modifier.py to modify .cklb files

* It will not overwrite the .cklb files, it will instead create a new directory and store the changed .cklb files there

* It generates a Summary CSV file aswell as the updated .cklb files

* Run stig_modifier.py

* "Load STIG Directory" - Select the folder that contains your .cklb STIG checklist files

* "Group ID (select)" - Select the Vuln ID that you would like to modify for all of the .cklb's in the selected STIG Directory

* "Status" - Select the status of the Vuln ID. i.e. open, not_reviewed, not_applicable or not_a_finding

* "Comments" - Add the text that you want in the comments field for the Vuln ID

* "Finding Details" - Add the text that you want in the finding details field for the Vuln ID

# 7. Developing Vulnerability Checks

**Each V-XXXXXX.py file is a self-contained module that must contain a single function named check.**


Function Signature: The check function must accept two arguments:

 * collected_data: A dictionary containing the raw, unprocessed command outputs from the device.

 * parsed_data: A dictionary containing the clean, structured data pre-processed by the appropriate parser.

Return Value: The check function must return a Python dictionary containing three specific keys:

+ 'status': A string with one of four possible values:

+ 'not_a_finding'

+ 'open'

+ 'not_applicable'

+ 'not_reviewed'

+ 'comments': A string containing a high-level summary of the check's result.

+ 'finding_details': A string (often multi-line) providing the specific evidence for the result. This should include the configuration lines that were checked, the reasons for a failure, or the evidence
