import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import re
import os
import subprocess
import configparser
import sys
from datetime import datetime

# Import our project modules
import data_collector
import stig_analyzer
import reporting_layer
import stig_summary 

# --- Global variables for the GUI ---
device_list_file_path = ""
device_ips = []
log_widget = None
output_path = ""

def initialize_paths(parent_window):
    """Checks for nct_stig.ini, creates it if not found, and ensures directories exist."""
    global output_path
    app_data_path = os.getenv('APPDATA')
    if not app_data_path:
        app_data_path = os.path.expanduser("~") # Fallback for non-windows or weird env
        
    nct_dir = os.path.join(app_data_path, 'NCT_STIG_Builder')
    ini_path = os.path.join(nct_dir, 'nct_stig.ini')

    config = configparser.ConfigParser()
    base_path = None

    if os.path.exists(ini_path):
        try:
            config.read(ini_path)
            base_path = config.get('Paths', 'StigReports', fallback=None)
            if base_path and not os.path.isdir(base_path):
                messagebox.showwarning("Path Not Found", f"The path in nct_stig.ini is invalid:\n{base_path}\nPlease select the directory again.", parent=parent_window)
                base_path = None
        except configparser.Error as e:
            messagebox.showwarning("INI File Error", f"Could not read nct_stig.ini: {e}\nPlease select the directory again.", parent=parent_window)
            base_path = None

    if not base_path:
        os.makedirs(nct_dir, exist_ok=True)
        messagebox.showinfo("Setup", "Please select a base directory for 'STIG Reports'.", parent=parent_window)
        
        selected_path = filedialog.askdirectory(title="Select Base Directory for STIG Reports", parent=parent_window)
        if not selected_path:
            messagebox.showerror("Error", "No directory selected. The application cannot continue.", parent=parent_window)
            sys.exit(1)
        
        base_path = os.path.join(selected_path, 'STIG Reports')
        config['Paths'] = {'StigReports': base_path}
        with open(ini_path, 'w') as configfile:
            config.write(configfile)

    os.makedirs(base_path, exist_ok=True)
    output_path = base_path
    return True


def select_device_list_file():
    """Opens a file dialog to select the device IPs file and loads its content."""
    global device_list_file_path
    file_path = filedialog.askopenfilename(
        title="Select the file containing device IPs",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
    )
    if file_path:
        device_list_file_path = file_path
        _load_ips_from_file()

def _load_ips_from_file():
    """Reads the selected file and extracts unique, valid IP addresses."""
    global device_ips
    if not device_list_file_path:
        return

    try:
        with open(device_list_file_path, "r") as f:
            content = f.read()
        
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips_found = re.findall(ip_pattern, content)
        
        device_ips.clear()
        device_ips.extend(list(dict.fromkeys(ips_found)))
        
        log_to_gui(f"Loaded {len(device_ips)} unique IP addresses from: {os.path.basename(device_list_file_path)}\n")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to read device file: {e}")
        log_to_gui(f"Error reading device file: {e}\n")

def open_preview_file():
    """Opens the selected device file using the default system application."""
    if device_list_file_path and os.path.exists(device_list_file_path):
        try:
            os.startfile(device_list_file_path)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open file: {e}")
    else:
        messagebox.showinfo("Info", "No device file has been loaded yet.")

def log_to_gui(message):
    """A thread-safe function to log messages to the GUI's text widget."""
    if log_widget:
        log_widget.insert(tk.END, message + "\n")
        log_widget.see(tk.END)
        log_widget.update_idletasks()

def run_full_stig_process(username, password):
    """
    The main worker function that orchestrates the entire STIG build process.
    """
    try:
        user_name = username
    except Exception:
        user_name = "user"
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_specific_folder_name = f"{user_name}_{timestamp}"
    final_output_path = os.path.join(output_path, run_specific_folder_name)
    os.makedirs(final_output_path, exist_ok=True)

    log_to_gui(f"--- Output directory for this run:\n{final_output_path}\n")

    all_devices_data = data_collector.collect_all_device_data(device_ips, username, password, log_to_gui)

    if not all_devices_data:
        log_to_gui("No data was collected from any device. Halting process.")
        return

    log_to_gui("\n--- Starting Analysis ---\n")
    all_analysis_results = stig_analyzer.analyze_all_devices(all_devices_data, log_to_gui)
    log_to_gui("\n--- Analysis Complete ---\n")

    log_to_gui("--- Starting Reporting ---")
    reporting_layer.generate_reports(all_analysis_results, all_devices_data, final_output_path, log_to_gui, username)
    log_to_gui("\n--- Reporting Complete ---\n")

    log_to_gui("--- Starting STIG Summary Generation ---")
    stig_summary.generate_summary(final_output_path, log_to_gui)
    log_to_gui("\n--- STIG Summary Generation Complete ---\n")
    
    log_to_gui("STIG Checklist build process finished.")

    log_to_gui(f"\nOpening output folder: {final_output_path}")
    try:
        os.startfile(final_output_path)
    except Exception as e:
        log_to_gui(f"Could not automatically open output folder: {e}")


def start_build_thread(username_var, password_var):
    """
    Validates inputs and starts the main STIG build process in a new thread.
    """
    username = username_var.get().strip()
    password = password_var.get().strip()


    if not username or not password:
        messagebox.showerror("Input Error", "Username and Password cannot be empty.")
        return
        
    if not device_ips:
        messagebox.showerror("Input Error", "Please load a device list file first.")
        return

    log_widget.delete('1.0', tk.END)
    threading.Thread(target=run_full_stig_process, args=(username, password), daemon=True).start()

def main():
    """Main function to create and run the Tkinter GUI."""
    global log_widget
    
    main_window = tk.Tk()
    
    if not initialize_paths(main_window):
        main_window.destroy()
        return

    main_window.title("STIG Checklist Builder")
    main_window.geometry("750x550")
    main_window.configure(bg="#f0f0f0")
    
    style = ttk.Style()
    style.configure('TFrame', background="#f0f0f0")
    style.configure('TLabel', background="#f0f0f0", font=('Arial', 10))
    style.configure('TButton', font=('Arial', 10), padding=[10, 5, 10, 5])
    style.configure("GreyBorder.TButton", borderwidth=1, relief="solid", foreground="black", width=12)

    main_frame = ttk.Frame(main_window, padding="10")
    main_frame.pack(fill="both", expand=True)

    username_var = tk.StringVar()
    password_var = tk.StringVar()
    
    cred_frame = ttk.Frame(main_frame)
    cred_frame.pack(fill='x', pady=(0, 5))
    cred_frame.columnconfigure(1, weight=1)

    ttk.Label(cred_frame, text="Username:").grid(row=0, column=0, sticky="w", padx=(0, 5))
    username_entry = ttk.Entry(cred_frame, textvariable=username_var)
    username_entry.grid(row=0, column=1, sticky="ew")
    
    ttk.Label(cred_frame, text="Password:").grid(row=1, column=0, sticky="w", padx=(0, 5), pady=(5,0))
    password_entry = ttk.Entry(cred_frame, textvariable=password_var, show="*")
    password_entry.grid(row=1, column=1, sticky="ew", pady=(5,0))
    
    file_frame = ttk.Frame(main_frame)
    file_frame.pack(fill='x', pady=10)
    file_frame.columnconfigure(0, weight=1)

    load_button = ttk.Button(file_frame, text="Load Device IPs File", command=select_device_list_file)
    load_button.grid(row=0, column=0, sticky="ew", padx=(0, 5))
    
    preview_button = ttk.Button(file_frame, text="Preview File", style="GreyBorder.TButton", command=open_preview_file)
    preview_button.grid(row=0, column=1, sticky="e")
    
    action_button = ttk.Button(
        main_frame, 
        text="Build STIG Checklist", 
        command=lambda: start_build_thread(username_var, password_var)
    )
    action_button.pack(fill='x', pady=15)

    log_widget = scrolledtext.ScrolledText(main_frame, height=15, bg="#ffffff", fg="black", font=('Arial', 9))
    log_widget.pack(fill="both", expand=True, pady=(5, 10))

    exit_button = ttk.Button(main_frame, text="Exit", command=main_window.destroy)
    exit_button.pack(fill='x')

    main_window.mainloop()

if __name__ == "__main__":
    main()

