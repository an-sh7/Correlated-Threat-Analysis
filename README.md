# Correlated Threat Analysis Script

This Python script automates the initial steps of a network forensics investigation by correlating IDS alerts with PCAP data.  It quickly identifies the likely infected host and extracts key information (MAC, hostname, user, potential malware URLs/hashes) to facilitate further analysis.

## Description

This script is designed to help security analysts and incident responders quickly triage potential security incidents. It takes two inputs:

1.  **A PCAP file:**  A network traffic capture (e.g., created by Wireshark, tcpdump, or other network monitoring tools).
2.  **An alerts file:**  A text file containing alerts from an Intrusion Detection System (IDS) or Network Detection and Response (NDR) system (e.g., Suricata, Snort, Zeek).  The script expects a common alert format that includes IP addresses.

The script performs the following actions:

1.  **Parses the Alerts File:**
    *   Identifies and counts the occurrences of IP addresses (both source and destination).
    *   Extracts potential malicious/external IP addresses (typically the source IPs in the alerts).
    *   Identifies URLs potentially related to the download of Windows executables.
    *   Determines the most likely infected internal host (prioritizing private IP addresses with the highest alert counts).

2.  **Analyzes the PCAP File:**
    *   Filters the PCAP data to focus on traffic related to the suspected infected host.
    *   Extracts the MAC address of the infected host.
    *   Attempts to extract the hostname from DNS, NBNS, or DHCP packets.
    *   Attempts to extract the Windows user account from SMB/SMB2 packets.
    *   Collects URLs that may be associated with malware downloads (from HTTP traffic).
    *   Calculates SHA256 hashes of potential malware payloads from TCP data streams.

3.  **Presents the Findings:**  Prints a summary of the analysis, including the identified infected host, its MAC address, hostname (if found), user account (if found), potential malicious URLs, and file hashes.

## Features

*   **Infected Host Identification:**  Quickly pinpoints the most likely compromised host based on alert frequency and IP address type (private vs. public).
*   **MAC Address Extraction:** Retrieves the MAC address of the infected host for network segmentation or device identification.
*   **Hostname and User Account Discovery:**  Attempts to identify the hostname and Windows user account associated with the infected host, providing valuable context.
*   **Malicious URL and Hash Detection:**  Identifies potential malware download URLs and calculates SHA256 hashes of suspicious payloads.
*   **External IP Identification:** Creates a list of suspected external attacker IPs.
*   **Easy to Use:**  Simple command-line execution with clear output.

## Dependencies

*   `pyshark`: A Python wrapper for TShark (the command-line version of Wireshark). Install using pip:
    ```bash
    pip install pyshark
    ```
* `ipaddress`: comes with python.
* **TShark:**  `pyshark` relies on TShark being installed on your system.  On most Linux distributions, you can install it with your package manager (e.g., `apt install tshark` on Debian/Ubuntu).  On Windows, you typically install Wireshark, which includes TShark. Make sure TShark is in your system's PATH.

## Usage

1.  **Clone this repository (or copy the script):**

    ```bash
    git clone <your_repository_url>
    cd <your_repository_directory>
    ```

2.  **Run the script:**

    ```bash
    python correlated_analysis.py  # Replace with the actual script name
    ```

    *   **Important:** The script assumes the PCAP file (`2019-02-23-traffic-analysis-exercise.pcap`) and the alerts file (`2019-02-23-traffic-analysis-exercise-alerts.txt`) are in the *same directory* as the script.  You may need to modify the `pcap_file` and `alerts_file` variables at the beginning of the script if your files are located elsewhere.  Ideally, you would add command-line argument parsing to make this more flexible.

3.  **Review the Output:** The script will print its findings to the console.

## Example

Assuming you have a PCAP file named `example.pcap` and an alerts file named `alerts.txt` in the same directory as the script, the output might look like this:
```
🚨 Correlated Threat Analysis 🚨

Infected Windows Host IP: 192.168.1.105
Infected Windows Host MAC: 00:11:22:33:44:55
Host Name: DESKTOP-XYZ123
Windows User Account Name: john.doe
Malicious URLs serving executables: ['http://malicious.example.com/payload.exe', 'http://anotherbadsite.com/malware.zip']
SHA256 hashes of the executables: ['a1b2c3d4e5f6...', 'f1e2d3c4b5a6...']
Malicious External IPs: ['203.0.113.5', '198.51.100.10']
```

## Limitations

*   This script provides a *basic* level of correlation.  It does not perform deep packet inspection, behavioral analysis, or threat intelligence lookups (beyond identifying potentially malicious IPs).
*   The accuracy of hostname and user account extraction depends on the presence and format of the relevant network traffic.
*   The script is designed for a specific alert file format. You may need to modify the regular expressions in the `parse_alerts` function if your alert file has a different structure.
*   Error handling is minimal.

## Improvements/TODO

*   **Command-line Arguments:** Add command-line arguments to specify the PCAP and alerts file paths, making the script more flexible.
*   **Configuration File:** Allow users to configure settings (e.g., alert file format, output format) via a configuration file.
*   **Output Options:**  Provide options to output the results in different formats (e.g., JSON, CSV).
*   **IP Reputation Lookup:** Integrate with services like VirusTotal or AbuseIPDB to check the reputation of identified IP addresses.
*   **More Robust Alert Parsing:**  Handle a wider variety of alert formats.
*   **Interactive Mode:**  Consider adding an interactive mode (perhaps using a simple text-based interface) to allow users to explore the data more thoroughly.
*   **Unit Tests:**  Add unit tests to ensure the script works correctly and to prevent regressions.
*   **Error Handling:**  Improve error handling to provide more informative messages to the user.
