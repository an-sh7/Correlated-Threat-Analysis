import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import pyshark
import hashlib
import re
import ipaddress
import asyncio
import json
import logging
import requests
from concurrent.futures import ThreadPoolExecutor
import random

# Configure logging for debugging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ---------------- Helper Functions ---------------- #

def is_private_ip(ip_addr):
    """Return True if the IP address is private."""
    try:
        return ipaddress.ip_address(ip_addr).is_private
    except ValueError:
        return False

def compute_file_hash(filepath):
    """Compute and return the SHA256 hash for the given file."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                hasher.update(block)
        return hasher.hexdigest()
    except Exception as e:
        logging.error(f"Hashing error for {filepath}: {e}")
        return "N/A"  # Return N/A instead of None for UI display

def lookup_ip_reputation(ip, api_key=None):
    """Query AbuseIPDB and return the reputation score, handling more errors."""
    if not api_key:
        return "API key not provided"
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {"Key": api_key, "Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raises HTTPError for bad responses (4xx or 5xx)
        data = response.json()
        if 'data' in data and 'abuseConfidenceScore' in data['data']:
            return data['data']['abuseConfidenceScore']
        elif 'errors' in data:
            # Handle API errors reported by AbuseIPDB
            return f"AbuseIPDB Error: {data['errors'][0]['detail']}"  # Show the first error detail
        else:
            return "Unexpected API response"
    except requests.exceptions.RequestException as e:
        return f"Request Error: {e}"  # More specific request error
    except (json.JSONDecodeError, KeyError) as e:
        return f"JSON/Data Error: {e}"  # Handle JSON parsing or data structure issues
    except Exception as e:
        return f"Unexpected Error: {e}"

def parse_zeek_log(log_path):
    """Parse a Zeek log file."""
    ip_counts = {}
    try:
        with open(log_path, "r") as file:
            for line in file:
                if line.startswith("#"):
                    continue
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    src_ip, dst_ip = parts[0], parts[1]
                    if not all([is_valid_ip(src_ip), is_valid_ip(dst_ip)]):  #validate the ips
                        continue
                    ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                    ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1

        private_ips = {ip: count for ip, count in ip_counts.items() if is_private_ip(ip)}
        # Prioritize private IPs, then public, otherwise return None
        return (max(private_ips, key=private_ips.get, default=None), set(), set()) if private_ips else \
               (max(ip_counts, key=ip_counts.get, default=None), set(), set())

    except Exception as err:
        logging.error(f"Error parsing Zeek log: {err}") # Log the error
        raise  # Re-raise to be caught by the caller

def is_valid_ip(ip_str):
    """Validates if the provided string is a valid IP address"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def parse_alert_file(alert_path):
    """Process an alerts file."""
    if alert_path.lower().endswith(".log"):
        return parse_zeek_log(alert_path)

    ip_counts = {}
    malicious_ips = set()
    exe_urls = set()
    try:
        with open(alert_path, "r") as file:
            for line in file:
                # More robust IP matching, handles surrounding characters.
                ip_matches = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                for ip in ip_matches:
                    if not is_valid_ip(ip): # Validate the extracted IP
                        continue
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
                    malicious_ips.add(ip)  # All IPs in alert file considered potentially malicious

                # Improved URL extraction, handles more variations
                if "ET MALWARE" in line or "EXE download" in line:
                    url_matches = re.findall(r'(https?://[^\s"<>]+)', line)
                    for url in url_matches:
                        exe_urls.add(url)

    except Exception as err:
        logging.error(f"Error parsing alerts file: {err}")  # Log
        raise # Re-raise

    private_ips = {ip: count for ip, count in ip_counts.items() if is_private_ip(ip)}
    # Prioritize private, then any IP, otherwise None
    target_ip = max(private_ips, key=private_ips.get, default=None) if private_ips else \
                max(ip_counts, key=ip_counts.get, default=None)
    return target_ip, malicious_ips, exe_urls

def process_packet(packet):
    """Extract key details from a network packet, with improved robustness."""
    details = {}
    try:
        if 'ip' in packet:
            details["src_ip"] = packet.ip.src
            details["dst_ip"] = packet.ip.dst
        if 'eth' in packet:
            details["mac"] = packet.eth.src
        if 'dns' in packet:
            details["hostname"] = getattr(packet.dns, "qry_name", None) or getattr(packet.dns, "resp_name", None)
        elif 'nbns' in packet:
            details["hostname"] = getattr(packet.nbns, "name", None)
        elif 'dhcp' in packet:
            details["hostname"] = getattr(packet.dhcp, "hostname", None)

        # Handle SMB and SMB2, getting the most likely username field.
        if 'smb' in packet or 'smb2' in packet:
            smb_layer = packet.smb if 'smb' in packet else packet.smb2
            for field in ['ntlmssp_auth_username', 'username', 'account', 'user']:
                username = getattr(smb_layer, field, None)
                if username:
                    details["user_account"] = username
                    break

        if 'http' in packet and hasattr(packet.http, "request_full_uri"):
            details.setdefault("exe_urls", set()).add(packet.http.request_full_uri)

        # Improved TCP payload handling, only process if data is present.
        if 'tcp' in packet and 'data' in packet:
            try:
                payload = bytes.fromhex(packet.data.data.replace(":", ""))
                exe_hash = hashlib.sha256(payload).hexdigest()
                details.setdefault("exe_hashes", set()).add(exe_hash)
            except (ValueError, AttributeError):  # Catch hex conversion and missing data errors
                pass

        if 'ssl' in packet:
            if hasattr(packet.ssl, 'handshake_type'):  #check for handshake
                details["tls_info"] = getattr(packet.ssl, "handshake_certificate", "N/A")
            else:
                details['tls_info'] = "N/A"

        if 'ftp' in packet:
            details["ftp_info"] = getattr(packet.ftp, "request_command", "N/A")

        if 'irc' in packet:
            details["irc_info"] = getattr(packet.irc, "data", "N/A")


    except Exception as err:
        logging.debug(f"Packet processing error: {err}")  # Detailed logging
    return details

def analyze_traffic(pcap_path, alert_path=None, ip_api_key=None):
    """Analyze PCAP and alerts, handling errors robustly."""
    results = {}
    results["PCAP File Hash"] = compute_file_hash(pcap_path)
    if alert_path:
        results["Alerts File Hash"] = compute_file_hash(alert_path)

    try:
        if alert_path:
            infected_ip, malicious_ips, exe_urls = parse_alert_file(alert_path)
        else:
            ip_counts = {}
            exe_urls = set()
            try:
                capture = pyshark.FileCapture(pcap_path)
                for pkt in capture:
                    if 'ip' in pkt:
                        ip_counts[pkt.ip.src] = ip_counts.get(pkt.ip.src, 0) + 1
                        ip_counts[pkt.ip.dst] = ip_counts.get(pkt.ip.dst, 0) + 1
                    if 'http' in pkt and hasattr(pkt.http, "request_full_uri"):
                        exe_urls.add(pkt.http.request_full_uri)
                capture.close()
            except Exception as e:
                return {"error": f"Error reading PCAP: {e}"}  # Specific PCAP error

            private_ips = {ip: cnt for ip, cnt in ip_counts.items() if is_private_ip(ip)}
            infected_ip = max(private_ips, key=private_ips.get, default=None) if private_ips else \
                          max(ip_counts, key=ip_counts.get, default=None)
            malicious_ips = set()  # Initialize even if no alert file

    except Exception as e:  # Catch errors from parse_alert_file
        return {"error": f"Alert processing error: {e}"}

    if not infected_ip:
        return {"error": "Could not determine the infected host IP."}

    results["Infected Windows Host IP"] = infected_ip
    results["IP Reputation Score"] = lookup_ip_reputation(infected_ip, ip_api_key) if ip_api_key else "Not checked"

    try:
        capture = pyshark.FileCapture(pcap_path, display_filter=f"ip.addr == {infected_ip}")
    except Exception as e:
        return {"error": f"Error filtering PCAP: {e}"}  # Filter error

    infected_mac = None
    hostname = None
    user_account = None
    all_urls = set(exe_urls)  # Use provided URLs or empty set
    all_hashes = set()

    packets = []
    try:
        for pkt in capture:
            packets.append(pkt)
    except Exception as e:
        capture.close()  # Close in case of error during iteration
        return {"error": f"Error iterating PCAP: {e}"}
    finally:
        capture.close() # Ensure closure

    with ThreadPoolExecutor(max_workers=4) as executor:
        packet_info = list(executor.map(process_packet, packets))

    for info in packet_info:
        if not infected_mac and "mac" in info:
            infected_mac = info["mac"]
        if not hostname and info.get("hostname"):
            hostname = info["hostname"]
        if not user_account and info.get("user_account"):
            user_account = info["user_account"]
        if "exe_urls" in info:
            all_urls.update(info["exe_urls"])
        if "exe_hashes" in info:
            all_hashes.update(info["exe_hashes"])

    results["Infected Windows Host MAC"] = infected_mac if infected_mac else "Not Found"
    results["Host Name"] = hostname if hostname else "Not Found (Check NBNS/DHCP)"
    results["Windows User Account Name"] = user_account if user_account else "Not Found (Check SMB)"
    results["Malicious URLs serving executables"] = list(all_urls)[:6]  # Limit to 6
    results["SHA256 hashes of the executables"] = list(all_hashes)[:6]  # Limit to 6
    results["Malicious External IPs"] = list(malicious_ips)

    return results

# ---------------- GUI Application ---------------- #

class TrafficAnalyzerGUI(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.master.title("Correlated Threat Analysis")
        self.style = ttk.Style(master)
        self._set_modern_style()
        self._build_menu()
        self._build_widgets()
        self.pcap_path = None
        self.alerts_path = None
        self.ip_api_key = None
        self.progress_running = False
        self.analysis_thread = None
        self.cancel_event = threading.Event()  # Event for cancellation


    def _set_modern_style(self):
      """Configure a modern, flat style for the UI."""
      self.style.theme_use("clam")
      default_font = ("Segoe UI", 10)
      bold_font = ("Segoe UI", 10, "bold")
      self.style.configure(".", font=default_font, foreground="#333333", background="#f0f0f0")
      self.master.configure(bg="#f0f0f0")

      # Buttons with hover effect
      self.style.configure("TButton", relief="flat", background="#3498db", foreground="white", padding=8, font=bold_font)
      self.style.map("TButton", background=[("active", "#2980b9"), ("disabled", "#cccccc")])

      # Entries
      self.style.configure("TEntry", padding=6, relief="flat", fieldbackground="#ffffff", borderwidth=1)

      # LabelFrames
      self.style.configure("TLabelframe", background="#f0f0f0", foreground="#333333", padding=10, font=bold_font)
      self.style.configure("TLabelframe.Label", background="#f0f0f0", foreground="#3498db", font=bold_font)

      # Header label
      self.style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground="#3498db", background="#f0f0f0", padding=(0, 10, 0, 20))

      # Progress bar (custom flat style)
      self.style.configure("TProgressbar", troughcolor="#ecf0f1", background="#3498db", thickness=20)

      # Scrollbar (for ScrolledText)
      self.style.configure("Vertical.TScrollbar", gripcount=0, background="#bdc3c7", troughcolor="#f0f0f0", arrowsize=16,
                            arrowcolor="white", relief="flat", borderwidth=0)
      self.style.map("Vertical.TScrollbar", background=[("active", "#95a5a6")])


    def _build_menu(self):
        """Build a simple menu bar with File and Help menus."""
        menubar = tk.Menu(self.master)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.master.quit, accelerator="Alt+F4")
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.master.config(menu=menubar)
        self.master.bind_all("<Alt-F4>", lambda event: self.master.quit())

    def _build_widgets(self):
        """Construct and layout the main UI widgets."""
        # Header
        header = ttk.Label(self, text="Correlated Threat Analysis", style="Header.TLabel")
        header.grid(row=0, column=0, columnspan=3, sticky="ew")

        # File selection frame
        file_frame = ttk.LabelFrame(self, text="Select Files")
        file_frame.grid(row=1, column=0, columnspan=3, padx=20, pady=10, sticky="ew")

        ttk.Label(file_frame, text="PCAP File:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.pcap_entry = ttk.Entry(file_frame, width=50)
        self.pcap_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(file_frame, text="Browse", command=self._browse_pcap).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(file_frame, text="Alerts File (Optional):").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.alerts_entry = ttk.Entry(file_frame, width=50)
        self.alerts_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(file_frame, text="Browse", command=self._browse_alerts).grid(row=1, column=2, padx=5, pady=5)

        ttk.Label(file_frame, text="AbuseIPDB API Key (Optional):").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.api_entry = ttk.Entry(file_frame, width=50, show="*")  # Mask API key
        self.api_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        file_frame.columnconfigure(1, weight=1) # Make entry fields expandable

        # Button frame
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=2, column=0, columnspan=3, padx=20, pady=10, sticky="ew")
        self.analyze_btn = ttk.Button(btn_frame, text="Run Analysis", command=self._start_analysis)
        self.analyze_btn.pack(side="left", padx=5)
        self.export_btn = ttk.Button(btn_frame, text="Export Results", command=self._export_results, state="disabled") # Initially disabled
        self.export_btn.pack(side="left", padx=5)
        self.stop_btn = ttk.Button(btn_frame, text="Cancel", command=self._cancel_analysis, state="disabled") # Initially disabled
        self.stop_btn.pack(side="left", padx=5)

        # Progress bar
        self.progress_frame = ttk.Frame(self)
        self.progress_frame.grid(row=3, column=0, columnspan=3, padx=20, sticky="ew")
        self.progress_bar = ttk.Progressbar(self.progress_frame, orient="horizontal", length=400, mode="indeterminate", style="TProgressbar")
        self.progress_bar.pack(fill="x", expand=True)

        # Results text area (with improved scrollbar)
        result_frame = ttk.LabelFrame(self, text="Analysis Results")
        result_frame.grid(row=4, column=0, columnspan=3, padx=20, pady=(10, 20), sticky="nsew")
        self.results_text = scrolledtext.ScrolledText(result_frame, width=80, height=20, wrap=tk.WORD, font=("Segoe UI", 10),
                                                        yscrollcommand=lambda f, l: self.auto_scroll(f, l)) # Auto scroll
        self.results_text.pack(fill="both", expand=True)
        self.scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.results_text.yview, style="Vertical.TScrollbar")
        self.scrollbar.pack(side="right", fill="y")
        self.results_text['yscrollcommand'] = self.scrollbar.set  # Connect scrollbar



        # Configure grid weights for responsiveness
        self.columnconfigure(0, weight=1)
        self.rowconfigure(4, weight=1)  # Make results area expand
        self.pack(fill="both", expand=True)


    def auto_scroll(self, first, last):
        """Auto-scroll the ScrolledText."""
        self.results_text.yview(tk.MOVETO, first)
        self.scrollbar.set(first, last)

    def _browse_pcap(self):
        """Open file dialog to select a PCAP file."""
        path = filedialog.askopenfilename(title="Select PCAP File", filetypes=[("PCAP Files", "*.pcap;*.pcapng"), ("All Files", "*.*")])
        if path:
            self.pcap_path = path
            self.pcap_entry.delete(0, tk.END)
            self.pcap_entry.insert(0, path)


    def _browse_alerts(self):
        """Open file dialog to select an Alerts file."""
        path = filedialog.askopenfilename(title="Select Alerts File", filetypes=[("Text/Log Files", "*.txt;*.log"), ("All Files", "*.*")])
        if path:
            self.alerts_path = path
            self.alerts_entry.delete(0, tk.END)
            self.alerts_entry.insert(0, path)

    def _start_progress(self):
        """Start the progress bar animation."""
        self.progress_running = True
        self.progress_bar.start(10)  # Slower animation

    def _stop_progress(self):
        """Stop the progress bar animation."""
        self.progress_running = False
        self.progress_bar.stop()


    def _start_analysis(self):
      """Initiate analysis, now with cancellation support."""
      if not self.pcap_path:
          messagebox.showerror("Missing File", "Please select a PCAP file.")
          return

      self.ip_api_key = self.api_entry.get().strip() or None
      self.analyze_btn.config(state="disabled")
      self.export_btn.config(state="disabled")  # Disable export during analysis
      self.stop_btn.config(state="normal")    # Enable cancel button
      self.results_text.delete("1.0", tk.END)
      self.results_text.insert(tk.END, "Running analysis... Please wait...\n")
      self._start_progress()
      self.cancel_event.clear()  # Reset cancellation event

      self.analysis_thread = threading.Thread(target=self._run_analysis, daemon=True)
      self.analysis_thread.start()

    def _cancel_analysis(self):
        """Cancel the running analysis."""
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.cancel_event.set()  # Signal the thread to stop
            self.results_text.insert(tk.END, "\nAnalysis cancelled by user.\n")
            self._stop_progress()
            self.analyze_btn.config(state="normal")
            self.export_btn.config(state="disabled")  # Keep export disabled after cancellation
            self.stop_btn.config(state="disabled")
            self.analysis_thread = None  # Clear the thread reference


    def _run_analysis(self):
        """Run the traffic analysis, checking for cancellation."""
        try:
            asyncio.set_event_loop(asyncio.new_event_loop())
            analysis = analyze_traffic(self.pcap_path, self.alerts_path, self.ip_api_key)

            if self.cancel_event.is_set():  # Check for cancellation
                return

            output = ""
            if "error" in analysis:
                output = "❌ Error: " + analysis["error"]
            else:
                output += "\n🚨 Correlated Threat Analysis 🚨\n\n"
                for key, value in analysis.items():
                    if key not in ("Malicious URLs serving executables", "SHA256 hashes of the executables", "Malicious External IPs"):
                        output += f"{key}: {value}\n"
                output += "\nMalicious URLs serving executables:\n" + "\n".join(analysis.get("Malicious URLs serving executables", [])) + "\n"
                output += "\nSHA256 hashes of the executables:\n" + "\n".join(analysis.get("SHA256 hashes of the executables", [])) + "\n"
                output += "\nMalicious External IPs:\n" + "\n".join(analysis.get("Malicious External IPs", [])) + "\n"

            self.results_text.after(0, lambda: self._display_results(output))  # Thread-safe update

        except Exception as e:  # Catch unexpected errors
            if not self.cancel_event.is_set():  # Don't show error if cancelled
               self.results_text.after(0, lambda: self._display_results(f"❌ Unexpected error: {e}"))

        finally:
            if not self.cancel_event.is_set(): # Only reset if not canceled
                self.results_text.after(0, lambda: self.analyze_btn.config(state="normal"))  # Thread-safe UI update
                self.results_text.after(0, lambda: self.export_btn.config(state="enabled"))
                self.results_text.after(0, lambda: self.stop_btn.config(state="disabled"))
                self.results_text.after(0, self._stop_progress)
                self.analysis_thread = None



    def _display_results(self, text):
        """Display analysis results, handling errors and normal output."""
        self.results_text.delete("1.0", tk.END)
        if "❌ Error:" in text:
            self.results_text.insert(tk.END, text, "error")
            self.results_text.tag_config("error", foreground="red")
        else:
            self.results_text.insert(tk.END, text)

    def _export_results(self):
        """Export results to a JSON file."""
        content = self.results_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showerror("No Results", "No analysis results to export.")
            return

        filepath = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")])
        if filepath:
            try:
                with open(filepath, "w") as f:
                    json.dump({"analysis_results": content}, f, indent=4)
                messagebox.showinfo("Export Successful", f"Results saved to {filepath}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save results: {e}")

    def _show_about(self):
        """Display an about dialog."""
        about_text = """
        Correlated Threat Analysis - Version 1.0

        This tool analyzes network traffic from PCAP files and correlates 
        it with optional alert files (e.g., Suricata, Zeek) to identify 
        potential threats.

        Features:
        - PCAP and alert file parsing
        - Identification of infected host (IP and MAC)
        - Hostname and user account extraction (if available)
        - Detection of malicious URLs and file hashes
        - IP reputation checking (using AbuseIPDB)
        - Export of results to JSON

        Dependencies:
        - pyshark
        - requests

        Author: Bard (with significant human assistance and corrections!)
        """
        messagebox.showinfo("About Correlated Threat Analysis", about_text)

def main():
    root = tk.Tk()
    app = TrafficAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
