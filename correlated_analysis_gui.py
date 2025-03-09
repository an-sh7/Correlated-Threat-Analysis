import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import pyshark
import hashlib
import re
import ipaddress
import asyncio

# ----- Analysis Functions -----

def is_private_ip(ip):
    """Check if an IP address is in a private range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def parse_alerts(alerts_file):
    """
    Parse the IDS alerts file to:
      - Count occurrences of each IP (source and destination),
      - Collect potential malicious (external) IPs,
      - Extract executable URLs for Windows executable alerts.
    Determine the infected (internal) host by selecting the private IP with the highest occurrence.
    """
    ip_counts = {}
    malicious_ips = set()
    exe_urls = set()

    try:
        with open(alerts_file, "r") as f:
            for line in f:
                # Extract IP pairs in the format: "A.B.C.D -> E.F.G.H"
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    src_ip, dst_ip = ip_match.groups()
                    # Count each occurrence for both source and destination
                    ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                    ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1
                    # Mark source IP as malicious (external attacker)
                    malicious_ips.add(src_ip)
                    # If alert indicates an executable download, extract the URL
                    if "ET MALWARE Windows executable" in line or "EXE download" in line:
                        url_match = re.search(r'(https?://[^\s]+)', line)
                        if url_match:
                            exe_urls.add(url_match.group(1))
    except Exception as e:
        raise Exception(f"Error parsing alerts file: {e}")

    # Select the infected host: choose the private IP with the highest count
    infected_ip = None
    private_ips = {ip: count for ip, count in ip_counts.items() if is_private_ip(ip)}
    if private_ips:
        infected_ip = max(private_ips, key=private_ips.get)
    elif ip_counts:
        infected_ip = max(ip_counts, key=ip_counts.get)

    return infected_ip, malicious_ips, exe_urls

def analyze_traffic(pcap_file, alerts_file=None):
    """
    Run the analysis:
      - If an alerts file is provided, parse it to determine the infected host IP.
      - Otherwise, analyze the PCAP to determine the most common (likely infected) IP.
      - Filter the PCAP for that IP,
      - Extract additional details: MAC address, hostname (from DNS/NBNS/DHCP),
        Windows user account (from SMB), executable URLs, and SHA256 hashes.
    Returns a dictionary containing the results.
    """
    results = {}

    # Determine infected IP using alerts file if provided; otherwise, analyze PCAP directly.
    if alerts_file:
        try:
            infected_ip, malicious_ips, exe_urls = parse_alerts(alerts_file)
        except Exception as e:
            return {"error": str(e)}
    else:
        # Analyze the PCAP file to count IP occurrences and extract potential executable URLs.
        ip_counts = {}
        exe_urls = set()
        try:
            cap = pyshark.FileCapture(pcap_file)
            for packet in cap:
                try:
                    # If packet has an IP layer, get src and dst IP addresses
                    if hasattr(packet, "ip"):
                        src_ip = getattr(packet.ip, "src", None)
                        dst_ip = getattr(packet.ip, "dst", None)
                        if src_ip:
                            ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                        if dst_ip:
                            ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1
                    # Look for additional executable URLs in HTTP requests
                    if hasattr(packet, "http") and hasattr(packet.http, "request_full_uri"):
                        exe_urls.add(packet.http.request_full_uri)
                except Exception:
                    continue
        finally:
            cap.close()
        
        private_ips = {ip: count for ip, count in ip_counts.items() if is_private_ip(ip)}
        if private_ips:
            infected_ip = max(private_ips, key=private_ips.get)
        elif ip_counts:
            infected_ip = max(ip_counts, key=ip_counts.get)
        else:
            return {"error": "No IP addresses found in PCAP file."}
        malicious_ips = set()  # Without alerts, external malicious IPs are not determined

    if not infected_ip:
        return {"error": "No infected host IP could be determined."}

    results["Infected Windows Host IP"] = infected_ip

    # Open the PCAP file with a display filter for the infected host IP
    try:
        cap = pyshark.FileCapture(pcap_file, display_filter=f"ip.addr == {infected_ip}")
    except Exception as e:
        return {"error": f"Error opening PCAP file: {e}"}

    infected_mac = None
    hostname = None
    user_account = None
    exe_hashes = set()

    try:
        for packet in cap:
            try:
                # Get the first seen MAC address from Ethernet packets
                if hasattr(packet, "eth") and not infected_mac:
                    infected_mac = packet.eth.src

                # Try to extract hostname from DNS, NBNS, or DHCP packets
                if not hostname:
                    if hasattr(packet, "dns"):
                        hostname = getattr(packet.dns, "qry_name", None) or getattr(packet.dns, "resp_name", None)
                    if hasattr(packet, "nbns") and not hostname:
                        hostname = getattr(packet.nbns, "name", None)
                    if hasattr(packet, "dhcp") and not hostname:
                        hostname = getattr(packet.dhcp, "hostname", None)

                # Extract Windows user account from SMB packets
                if not user_account:
                    if hasattr(packet, "smb"):
                        user_account = getattr(packet.smb, "ntlmssp_auth_username", None) or getattr(packet.smb, "ntlmssp_auth_user", None)
                    if hasattr(packet, "smb.old") and not user_account:
                        user_account = getattr(packet.smb.old, "ntlmssp_auth_username", None)

                # Look for additional executable URLs in HTTP requests
                if hasattr(packet, "http") and hasattr(packet.http, "request_full_uri"):
                    exe_urls.add(packet.http.request_full_uri)

                # Compute SHA256 hash for packets with TCP data carrying a file transfer
                if hasattr(packet, "tcp") and hasattr(packet, "data"):
                    hex_data = packet.data.data.replace(":", "")
                    try:
                        data_payload = bytes.fromhex(hex_data)
                        sha256_hash = hashlib.sha256(data_payload).hexdigest()
                        exe_hashes.add(sha256_hash)
                    except ValueError:
                        pass  # skip packets that fail hex conversion

            except Exception:
                continue
    finally:
        cap.close()

    results["Infected Windows Host MAC"] = infected_mac if infected_mac else "Not Found"
    results["Host Name"] = hostname if hostname else "Not Found (Check NBNS/DHCP in Wireshark)"
    results["Windows User Account Name"] = user_account if user_account else "Not Found (Check SMB packets)"
    results["Malicious URLs serving executables"] = list(exe_urls)[:6]
    results["SHA256 hashes of the executables"] = list(exe_hashes)[:6]
    results["Malicious External IPs"] = list(malicious_ips)

    return results

# ----- GUI Code -----

class TrafficAnalyzerGUI(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.parent.title("Correlated Threat Analysis")
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.create_widgets()

        # Variables to store selected file paths
        self.pcap_file = None
        self.alerts_file = None  # optional

    def create_widgets(self):
        # File selection frame
        file_frame = ttk.LabelFrame(self, text="Select Files", padding=(10, 10))
        file_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        # PCAP file selection
        ttk.Label(file_frame, text="PCAP File:").grid(row=0, column=0, sticky="w")
        self.pcap_entry = ttk.Entry(file_frame, width=50)
        self.pcap_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_pcap).grid(row=0, column=2, padx=5)

        # Alerts file selection (optional)
        ttk.Label(file_frame, text="Alerts File (Optional):").grid(row=1, column=0, sticky="w")
        self.alerts_entry = ttk.Entry(file_frame, width=50)
        self.alerts_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_alerts).grid(row=1, column=2, padx=5)

        # Analysis button
        self.analyze_button = ttk.Button(self, text="Run Analysis", command=self.run_analysis)
        self.analyze_button.grid(row=2, column=0, padx=10, pady=(0, 10))

        # Results display frame
        result_frame = ttk.LabelFrame(self, text="Analysis Results", padding=(10, 10))
        result_frame.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")
        self.results_text = scrolledtext.ScrolledText(result_frame, width=80, height=20, wrap=tk.WORD)
        self.results_text.pack(fill="both", expand=True)

        # Configure grid weights for responsiveness
        self.parent.columnconfigure(0, weight=1)
        self.parent.rowconfigure(3, weight=1)
        self.pack(fill="both", expand=True)

    def browse_pcap(self):
        filename = filedialog.askopenfilename(title="Select PCAP File",
                                              filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")])
        if filename:
            self.pcap_file = filename
            self.pcap_entry.delete(0, tk.END)
            self.pcap_entry.insert(0, filename)

    def browse_alerts(self):
        filename = filedialog.askopenfilename(title="Select Alerts File",
                                              filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if filename:
            self.alerts_file = filename
            self.alerts_entry.delete(0, tk.END)
            self.alerts_entry.insert(0, filename)

    def run_analysis(self):
        if not self.pcap_file:
            messagebox.showerror("Missing File", "Please select at least a PCAP file.")
            return

        # Disable the button while processing and clear previous results
        self.analyze_button.config(state="disabled")
        self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, "Analysis running, please wait...\n")

        # Run the analysis in a separate thread to avoid freezing the GUI
        threading.Thread(target=self.do_analysis, daemon=True).start()

    def do_analysis(self):
        # Ensure a new event loop is created for this thread
        asyncio.set_event_loop(asyncio.new_event_loop())
        results = analyze_traffic(self.pcap_file, self.alerts_file)
        output = ""
        if "error" in results:
            output = "❌ Error: " + results["error"]
        else:
            output += "\n🚨 **Correlated Threat Analysis** 🚨\n\n"
            output += f"Infected Windows Host IP: {results.get('Infected Windows Host IP')}\n"
            output += f"Infected Windows Host MAC: {results.get('Infected Windows Host MAC')}\n"
            output += f"Host Name: {results.get('Host Name')}\n"
            output += f"Windows User Account Name: {results.get('Windows User Account Name')}\n"
            output += "Malicious URLs serving executables: " + ", ".join(results.get("Malicious URLs serving executables", [])) + "\n"
            output += "SHA256 hashes of the executables: " + ", ".join(results.get("SHA256 hashes of the executables", [])) + "\n"
            output += "Malicious External IPs: " + ", ".join(results.get("Malicious External IPs", [])) + "\n"

        # Update the GUI with the results on the main thread
        self.results_text.after(0, lambda: self.update_results(output))

    def update_results(self, text):
        self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, text)
        self.analyze_button.config(state="normal")

def main():
    root = tk.Tk()
    app = TrafficAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
