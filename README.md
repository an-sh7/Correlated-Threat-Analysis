# Correlated Threat Analysis Tool (GUI Version)

This Python application provides a graphical user interface (GUI) for performing correlated threat analysis using PCAP files and optional IDS/NDR alert logs. It helps security analysts quickly identify potentially compromised hosts and gather initial indicators of compromise (IOCs). This is an enhanced version of a command-line script, now with a user-friendly interface.

## Description

The tool combines network traffic analysis (from PCAP files) with alert data (from systems like Suricata, Snort, or Zeek) to provide a more comprehensive view of potential security incidents. It automates several key steps in the initial stages of an investigation, including:

- **Identifying the most likely infected host:** Based on IP address frequency and whether the IP is private or public.
- **Extracting key information about the infected host:** MAC address, hostname (if available via DNS, NBNS, or DHCP), and Windows user account (if available via SMB/SMB2).
- **Detecting potential malware downloads:** Identifying URLs that may have delivered malicious executables and calculating SHA256 hashes of suspicious network payloads.
- **Listing potentially malicious external IP addresses:** Based on the source IPs found in the alert logs.

## Features

- **Graphical User Interface (GUI):** Easy-to-use interface built with Tkinter.
- **PCAP File Analysis:** Processes network traffic captures using the powerful `pyshark` library.
- **Optional Alert Log Integration:** Supports correlation with alert files from various IDS/NDR systems (text-based formats).
- **Infected Host Identification:** Prioritizes private IP addresses with the highest alert counts to pinpoint compromised systems.
- **MAC Address, Hostname, and User Account Extraction:** Gathers crucial context about the infected host (when available in the network traffic).
- **Malicious URL and Hash Detection:** Flags potential malware download URLs and calculates SHA256 hashes.
- **External IP Identification:** Compiles a list of potentially malicious external IP addresses.
- **Multi-threaded Analysis:** Runs the analysis in a separate thread to prevent the GUI from freezing.
- **Error Handling:** Includes robust error handling to gracefully manage issues with file parsing, network traffic, and user input. Error messages are displayed in the GUI.
- **Logging:** Logs debug information to the console.

## Dependencies

- **Python 3.6+:** This script is written in Python 3.
- **pyshark:** A Python wrapper for TShark.
  
  ```bash
  pip install pyshark
  ```
  
- **TShark:** `pyshark` depends on TShark. You likely have this if you have Wireshark installed. Ensure TShark is in your system's PATH. On Linux, you can often install it via your package manager (e.g., `apt install tshark` on Debian/Ubuntu).
- **ipaddress:** Comes with Python.

## Installation

1. **Clone the repository (or download the script):**

    ```bash
    git clone <your_repository_url>
    cd <your_repository_directory>
    ```

2. **Install the `pyshark` library:**

    ```bash
    pip install pyshark
    ```

3. **Ensure TShark is installed and in your PATH:** See the "Dependencies" section above.

## Usage

1. **Run the script:**

    ```bash
    python correlated_analysis_gui.py  # Replace with the actual script name
    ```

2. **Select Files:**
    - Click the "Browse" button next to "PCAP File:" to choose your PCAP file (`.pcap` or `.pcapng`).
    - (Optional) Click the "Browse" button next to "Alerts File (Optional):" to select a text-based alert log file (`.txt` or `.log`).

3. **Run the Analysis:**
    - Click the "Run Analysis" button. The analysis will run in the background, and a progress indicator will be displayed. The GUI will remain responsive.

4. **View Results:**
    - The results will be displayed in the "Analysis Results" text area. This includes:
      - Infected Windows Host IP
      - Infected Windows Host MAC
      - Host Name (if found)
      - Windows User Account Name (if found)
      - Malicious URLs serving executables (up to 6)
      - SHA256 hashes of the executables (up to 6)
      - Malicious External IPs

5. **Error Handling:**
    - If errors occur, the program will not crash but will instead log them and attempt to inform the user.

## Example Output

🚨 **Correlated Threat Analysis** 🚨

```
Infected Windows Host IP: 192.168.1.105
Infected Windows Host MAC: 00:11:22:33:44:55
Host Name: DESKTOP-WORKSTATION
Windows User Account Name: john.doe
Malicious URLs serving executables: http://example.com/malware.exe, http://badsite.com/payload.zip
SHA256 hashes of the executables: a1b2c3d4..., f1e2d3c4...
Malicious External IPs: 203.0.113.5, 198.51.100.10
```

## Limitations

- The accuracy of hostname and user account identification depends on the presence and format of the relevant network traffic (DNS, NBNS, DHCP, SMB).
- The alert file parsing is designed for common text-based formats. You may need to adjust the regular expressions if your alert file has a significantly different structure.
- The tool does not currently include advanced features like threat intelligence lookups (e.g., VirusTotal integration).

## Future Improvements

- **IP Reputation Lookup:** Integrate with services like VirusTotal or AbuseIPDB to provide reputation scores for identified IP addresses.
- **Export Results:** Add options to export the analysis results to different file formats (e.g., CSV, JSON).
- **Configurable Alert Parsing:** Allow users to define custom regular expressions or parsing rules for different alert file formats.
- **More Detailed Packet Information:** Provide an option to display more detailed information about specific packets related to the incident.
- **Interactive Exploration:** Potentially add features for interactive exploration of the network traffic data.

