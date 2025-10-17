import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import json
from datetime import datetime
import csv # Added for CSV generation

# --- CSV Generation Functions (Provided by user) ---
def process_cklb_file(filename):
    """
    Processes a single .cklb file and extracts vulnerability information.
    """
    vulnerabilities = []
    with open(filename, 'r', encoding='utf-8') as f: # Ensure utf-8 encoding
        try:
            data = json.load(f)
            # Safely get hostname and IP address, provide defaults if not found
            hostname = data.get('target_data', {}).get('host_name', 'N/A')
            ip_address = data.get('target_data', {}).get('ip_address', 'N/A')

            if "stigs" in data and isinstance(data["stigs"], list):
                for stigs in data['stigs']:
                    if "rules" in stigs and isinstance(stigs["rules"], list):
                        for rule in stigs['rules']:
                            remediation = ""
                            finding = rule.get('finding_details', '')

                            if rule.get('status') == 'open':
                                remediation = rule.get('comments', '')

                            # Handle leading hyphens in remediation and finding
                            if remediation.startswith("-"):
                                remediation = "'" + remediation
                            if finding.startswith("-"):
                                finding = "'" + finding

                            vulnerability = {
                                'Hostname': hostname,
                                'IP address': ip_address,
                                'Vulnerability ID': rule.get('group_id', 'N/A'),
                                'Severity': rule.get('severity', 'N/A'),
                                'Status': rule.get('status', 'N/A'),
                                'STIG ID': stigs.get('stig_id', 'N/A'),
                                'Finding': finding,
                                'Remediation': remediation
                            }
                            vulnerabilities.append(vulnerability)

        except (json.JSONDecodeError, KeyError) as e:
            print(f"Error processing {filename}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred while processing {filename}: {e}")

    return vulnerabilities

def generate_csv_summary(ckl_output_path):
    """
    Generates a CSV file summarizing vulnerabilities from .cklb files
    in the specified output path.
    """
    now = datetime.now()
    file_name = now.strftime(f"STIG_Summary_%Y%m%d-%H%M%S") # Added timestamp for uniqueness
    output_file = os.path.join(ckl_output_path, f'{file_name}.csv')
    fieldnames = ['Hostname', 'IP address', 'STIG ID', 'Vulnerability ID', 'Severity', 'Status', 'Finding' , 'Remediation']

    all_vulnerabilities = []

    # Ensure the output directory exists before listing files
    if not os.path.exists(ckl_output_path):
        print(f"Error: Output directory '{ckl_output_path}' does not exist for CSV generation.")
        return

    for filename in os.listdir(ckl_output_path):
        if filename.endswith('.cklb'):
            file_path = os.path.join(ckl_output_path, filename)
            vulnerabilities = process_cklb_file(file_path)
            all_vulnerabilities.extend(vulnerabilities)

    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile: # Ensure utf-8 encoding
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for vulnerability in all_vulnerabilities:
                writer.writerow(vulnerability)
        print(f"CSV summary generated successfully at: {output_file}")
        return output_file # Return the path to the generated CSV
    except Exception as e:
        print(f"Error writing CSV file: {e}")
        return None

# --- Main Application Class ---
class STIGModifierApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Configuration Tool - STIG Checklist Modifier")
        self.root.geometry("1000x800") # Set a reasonable default window size

        # Apply the 'clam' theme
        style = ttk.Style()
        style.theme_use('clam')

        # Configure styles for better appearance
        style.configure('TFrame', background='#e0e0e0')
        style.configure('TLabel', background='#e0e0e0', font=('Inter', 10))
        style.configure('TButton', font=('Inter', 10, 'bold'), padding=6)
        style.configure('TEntry', font=('Inter', 10), padding=3)
        style.configure('TText', font=('Inter', 10), padding=3)
        style.configure('TListbox', font=('Inter', 10))
        style.configure('TCombobox', font=('Inter', 10), padding=3) # Style for Combobox

        self.stig_directory = ""
        self.cklb_files = []
        self.rule_input_frames = [] # To keep track of dynamically added rule input sections
        self.all_group_ids = set() # To store unique Group IDs found in loaded files
        self.sorted_group_ids = [] # Sorted list for combobox values

        # Predefined STIG statuses for the dropdown (removed "finding")
        self.stig_statuses = ["not_a_finding", "open", "not_applicable", "not_reviewed"]

        self.create_widgets()

    def create_widgets(self):
        # --- Directory Selection Frame ---
        dir_frame = ttk.Frame(self.root, padding="15", relief="groove", borderwidth=2)
        dir_frame.pack(fill=tk.X, padx=15, pady=10)

        ttk.Label(dir_frame, text="STIG Checklist Directory:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.dir_path_label = ttk.Label(dir_frame, text="No directory selected", foreground="blue")
        self.dir_path_label.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        load_dir_button = ttk.Button(dir_frame, text="Load STIG Directory", command=self.load_stig_directory)
        load_dir_button.grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(dir_frame, text="Found .cklb Files:").grid(row=1, column=0, padx=5, pady=5, sticky="nw")
        self.file_listbox = tk.Listbox(dir_frame, height=5, width=60, selectmode=tk.SINGLE, background="#f8f8f8")
        self.file_listbox.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        file_list_scrollbar = ttk.Scrollbar(dir_frame, orient="vertical", command=self.file_listbox.yview)
        file_list_scrollbar.grid(row=1, column=3, sticky="ns")
        self.file_listbox.config(yscrollcommand=file_list_scrollbar.set)

        dir_frame.grid_columnconfigure(1, weight=1) # Allow directory path label to expand

        # --- Rule Modification Frame (Scrollable) ---
        # Create a canvas to hold the scrollable frame
        self.canvas = tk.Canvas(self.root, background='#f0f0f0', relief="sunken", borderwidth=1)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=15, pady=10)

        # Create a scrollbar for the canvas
        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        # Bind the canvas scrollregion update to its size changes
        self.canvas.bind('<Configure>', lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        # Create a frame inside the canvas to hold the rule input sections
        self.rule_input_container = ttk.Frame(self.canvas, padding="15")
        # Place the container frame inside the canvas
        self.canvas_window_id = self.canvas.create_window((0, 0), window=self.rule_input_container, anchor="nw", width=self.canvas.winfo_width())

        # Bind the container frame's size to update the canvas scrollregion
        self.rule_input_container.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        # Bind the canvas width to the container frame's width for responsiveness
        self.canvas.bind('<Configure>', self.on_canvas_configure)


        # --- Add/Apply Buttons Frame ---
        action_buttons_frame = ttk.Frame(self.root, padding="15")
        action_buttons_frame.pack(fill=tk.X, padx=15, pady=10)

        add_rule_button = ttk.Button(action_buttons_frame, text="+ Add Another STIG Rule", command=self.add_rule_fields)
        add_rule_button.pack(side=tk.LEFT, padx=5)

        apply_button = ttk.Button(action_buttons_frame, text="Apply Changes to Checklists", command=self.apply_changes)
        apply_button.pack(side=tk.RIGHT, padx=5)

        self.status_label = ttk.Label(self.root, text="Ready.", foreground="green", font=('Inter', 10, 'italic'))
        self.status_label.pack(fill=tk.X, padx=15, pady=5)

        # Add initial rule fields
        self.add_rule_fields()

    def on_canvas_configure(self, event):
        # Update the width of the frame inside the canvas when the canvas itself resizes
        # This ensures the inner frame expands/contracts with the canvas
        self.canvas.itemconfig(self.canvas_window_id, width=event.width)
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))


    def load_stig_directory(self):
        directory = filedialog.askdirectory(title="Select STIG Checklist Directory")
        if directory:
            self.stig_directory = directory
            self.dir_path_label.config(text=self.stig_directory)
            self.cklb_files = []
            self.file_listbox.delete(0, tk.END)
            self.all_group_ids = set() # Reset group IDs for new directory

            for root_dir, _, files in os.walk(self.stig_directory):
                for file in files:
                    if file.endswith(".cklb"):
                        full_path = os.path.join(root_dir, file)
                        self.cklb_files.append(full_path)
                        self.file_listbox.insert(tk.END, file)

                        # Attempt to parse file to extract Group IDs
                        try:
                            with open(full_path, 'r', encoding='utf-8') as f:
                                content = f.read().strip()
                                data = json.loads(content)

                                # Navigate the nested structure: data -> "stigs" array -> each stig -> "rules" array -> each rule
                                if "stigs" in data and isinstance(data["stigs"], list):
                                    for stig in data["stigs"]:
                                        if "rules" in stig and isinstance(stig["rules"], list):
                                            for rule_data in stig["rules"]:
                                                if "group_id" in rule_data:
                                                    self.all_group_ids.add(rule_data["group_id"])
                                else:
                                    # This warning indicates the top-level structure is not as expected
                                    print(f"Warning: File {file} does not contain expected 'stigs' or 'rules' structure at the top level.")

                        except json.JSONDecodeError as e:
                            print(f"Warning: Could not parse {file} as JSON. Error: {e}")
                            print(f"Content snippet: {content[:200]}...") # Print a snippet for debugging
                        except Exception as e:
                            print(f"Warning: An unexpected error occurred while parsing {file}: {e}")
                            # Continue processing other files even if one fails

            self.sorted_group_ids = sorted(list(self.all_group_ids))
            # Debugging print to confirm extracted Group IDs
            print(f"Extracted Group IDs: {self.sorted_group_ids}")
            self._update_group_id_comboboxes() # Update all existing comboboxes

            self.status_label.config(text=f"Found {len(self.cklb_files)} .cklb files. Extracted {len(self.sorted_group_ids)} unique Group IDs.", foreground="blue")
        else:
            self.status_label.config(text="Directory selection cancelled.", foreground="orange")

    def _update_group_id_comboboxes(self):
        """Updates the values in all Group ID comboboxes."""
        for rule_input in self.rule_input_frames:
            # Check if the combobox exists for this rule input frame
            if "group_id_combobox" in rule_input["entries"] and rule_input["entries"]["group_id_combobox"]:
                rule_input["entries"]["group_id_combobox"]['values'] = self.sorted_group_ids


    def add_rule_fields(self):
        # Create a new frame for each rule input section
        rule_frame = ttk.Frame(self.rule_input_container, padding="10", relief="ridge", borderwidth=1)
        rule_frame.pack(fill=tk.X, padx=5, pady=5)

        # Store entry/text widgets for later retrieval of values
        rule_entries = {
            "group_id": tk.StringVar(),
            "status": tk.StringVar(),
            "comments_text_widget": None, # Will store the Text widget itself
            "finding_details_text_widget": None, # Will store the Text widget itself
            "group_id_combobox": None, # Will store the Group ID Combobox
            "status_combobox": None # Will store the Status Combobox
        }

        row_idx = 0

        # Group ID - now a Combobox (state changed to readonly as requested)
        ttk.Label(rule_frame, text="Group ID (select):").grid(row=row_idx, column=0, padx=5, pady=2, sticky="w")
        group_id_combobox = ttk.Combobox(rule_frame, textvariable=rule_entries["group_id"],
                                         values=self.sorted_group_ids, state="readonly", width=30)
        group_id_combobox.grid(row=row_idx, column=1, padx=5, pady=2, sticky="ew")
        rule_entries["group_id_combobox"] = group_id_combobox
        row_idx += 1

        # Status - now a Combobox
        ttk.Label(rule_frame, text="Status:").grid(row=row_idx, column=0, padx=5, pady=2, sticky="w")
        status_combobox = ttk.Combobox(rule_frame, textvariable=rule_entries["status"],
                                       values=self.stig_statuses, state="readonly", width=30)
        status_combobox.grid(row=row_idx, column=1, padx=5, pady=2, sticky="ew")
        rule_entries["status_combobox"] = status_combobox
        row_idx += 1

        # Comments
        ttk.Label(rule_frame, text="Comments:").grid(row=row_idx, column=0, padx=5, pady=2, sticky="nw")
        comments_text = tk.Text(rule_frame, height=4, width=50, wrap="word", background="#f8f8f8")
        comments_text.grid(row=row_idx, column=1, padx=5, pady=2, sticky="ew")
        rule_entries["comments_text_widget"] = comments_text
        row_idx += 1

        # Finding Details
        ttk.Label(rule_frame, text="Finding Details:").grid(row=row_idx, column=0, padx=5, pady=2, sticky="nw")
        finding_details_text = tk.Text(rule_frame, height=4, width=50, wrap="word", background="#f8f8f8")
        finding_details_text.grid(row=row_idx, column=1, padx=5, pady=2, sticky="ew")
        rule_entries["finding_details_text_widget"] = finding_details_text
        row_idx += 1

        # Remove button for this rule section
        remove_button = ttk.Button(rule_frame, text="Remove This Rule",
                                   command=lambda: self.remove_rule_fields(rule_frame, rule_entries))
        remove_button.grid(row=row_idx, column=1, padx=5, pady=5, sticky="e")

        rule_frame.grid_columnconfigure(1, weight=1) # Allow entry/text widgets to expand

        self.rule_input_frames.append({"frame": rule_frame, "entries": rule_entries})

        # Update the scrollable region of the canvas
        self.root.update_idletasks() # Ensure widgets are rendered before calculating bbox
        self.canvas.config(scrollregion=self.canvas.bbox("all"))

    def remove_rule_fields(self, frame_to_destroy, entries_to_remove):
        # Find and remove the frame from the list
        for i, item in enumerate(self.rule_input_frames):
            if item["frame"] == frame_to_destroy:
                self.rule_input_frames.pop(i)
                break
        frame_to_destroy.destroy()
        self.root.update_idletasks() # Ensure widgets are removed before recalculating bbox
        self.canvas.config(scrollregion=self.canvas.bbox("all"))


    def apply_changes(self):
        if not self.cklb_files:
            messagebox.showwarning("No Files Loaded", "Please load a STIG directory first.")
            return

        if not self.rule_input_frames:
            messagebox.showwarning("No Rules to Modify", "Please add at least one STIG rule to modify.")
            return

        # Create a new output directory with a timestamp
        timestamp = datetime.now().strftime("%Y%m%d-%H-%M-%S")
        output_dir_name = f"NCT-Modified STIGs-{timestamp}"
        output_directory_path = os.path.join(self.stig_directory, output_dir_name)

        try:
            os.makedirs(output_directory_path, exist_ok=True)
            self.status_label.config(text=f"Creating output directory: {output_directory_path}", foreground="blue")
        except OSError as e:
            messagebox.showerror("Directory Creation Error", f"Failed to create output directory: {e}")
            self.status_label.config(text="Failed to create output directory.", foreground="red")
            return

        modified_count = 0
        file_errors = []

        for cklb_file_path in self.cklb_files:
            try:
                with open(cklb_file_path, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    data = json.loads(content)

                file_modified = False
                # Iterate through the rules in the loaded data to find and modify
                if "stigs" in data and isinstance(data["stigs"], list):
                    for stig in data["stigs"]:
                        if "rules" in stig and isinstance(stig["rules"], list):
                            for rule_data in stig["rules"]:
                                for rule_input in self.rule_input_frames:
                                    group_id_to_match = rule_input["entries"]["group_id"].get().strip()
                                    new_status = rule_input["entries"]["status"].get().strip()
                                    new_comments = rule_input["entries"]["comments_text_widget"].get("1.0", tk.END).strip()
                                    new_finding_details = rule_input["entries"]["finding_details_text_widget"].get("1.0", tk.END).strip()

                                    if not group_id_to_match:
                                        continue # Skip if Group ID is empty for this rule input

                                    if rule_data.get("group_id") == group_id_to_match:
                                        rule_data["status"] = new_status
                                        rule_data["comments"] = new_comments
                                        rule_data["finding_details"] = new_finding_details
                                        file_modified = True
                                        # No break here, as one file might contain multiple rules to modify
                                        # from different user input sections.

                if file_modified:
                    # Construct the new file path in the output directory
                    output_file_path = os.path.join(output_directory_path, os.path.basename(cklb_file_path))
                    with open(output_file_path, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=4) # Use indent for pretty printing
                    modified_count += 1

            except json.JSONDecodeError as e:
                file_errors.append(f"{os.path.basename(cklb_file_path)} (JSON Error: {e})")
            except Exception as e:
                file_errors.append(f"{os.path.basename(cklb_file_path)} (Error: {e})")

        # After all .cklb files are processed and saved, generate the CSV summary
        csv_file_path = None
        if not file_errors: # Only generate CSV if no critical errors occurred during file modification
            try:
                csv_file_path = generate_csv_summary(output_directory_path)
            except Exception as e:
                messagebox.showerror("CSV Generation Error", f"Failed to generate CSV summary: {e}")
                self.status_label.config(text=f"Applied changes to {modified_count} files, but CSV generation failed.", foreground="red")
                return

        if file_errors:
            error_message = "Errors occurred in the following files during modification:\n" + "\n".join(file_errors)
            if csv_file_path:
                error_message += f"\n\nCSV summary was still generated at '{os.path.basename(csv_file_path)}'."
            messagebox.showerror("Modification Errors", error_message)
            self.status_label.config(text=f"Applied changes to {modified_count} files with errors. Output to '{output_dir_name}'.", foreground="red")
        else:
            success_message = f"Successfully applied changes to {modified_count} files.\nAll modified files are saved in the '{output_dir_name}' folder."
            if csv_file_path:
                success_message += f"\nCSV summary generated at: '{os.path.basename(csv_file_path)}'."
            self.status_label.config(text=success_message, foreground="green")
            messagebox.showinfo("Success", success_message)


if __name__ == "__main__":
    root = tk.Tk()
    app = STIGModifierApp(root)
    root.mainloop()
