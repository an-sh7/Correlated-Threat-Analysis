# Correlated Threat Analysis Tool

This tool analyzes network traffic captured in PCAP files and optionally correlates it with alerts from intrusion detection/prevention systems (like Suricata or Zeek) to identify potential security threats.  It's designed to assist in incident response and network forensics investigations.

## Features

*   **PCAP Parsing:**  Analyzes network traffic from PCAP and PCAPNG files using the `pyshark` library (a Python wrapper for TShark).
*   **Alert File Correlation:**  Supports parsing and correlation with alert files from:
    *   **Suricata:**  Parses standard Suricata alert files.
    *   **Zeek (Bro):**  Parses Zeek log files.
    * **Generic Alert Files:** Can process alert files in simple text formats.
*   **Infected Host Identification:**  Determines the likely infected host's IP address (prioritizing private IPs) and attempts to extract its MAC address.
*   **Host and User Information:**  Attempts to extract:
    *   **Hostname:**  From DNS, NBNS, or DHCP packets.
    *   **Windows User Account:** From SMB/SMB2 traffic (looks for common username fields).
*   **Malicious Activity Detection:**
    *   **Malicious URLs:**  Identifies URLs potentially serving executables (from HTTP traffic and alert data).
    *   **Executable Hashes:**  Calculates SHA256 hashes of potential executable payloads extracted from TCP data streams.
    *  **Malicious IPs:** Extracts potential IPs from alert file.
*   **IP Reputation Check (Optional):**  Integrates with the [AbuseIPDB API](https://www.abuseipdb.com/) to check the reputation score of the identified infected host IP address.  Requires a free AbuseIPDB API key.
*   **Detailed Packet Analysis:** Extracts and handles:
    - TLS/SSL certificate info.
    - FTP Command
    - IRC Data
*   **Result Export:**  Exports the analysis findings to a JSON file for easy sharing and reporting.
*   **User-Friendly GUI:**  Provides a graphical interface built with Tkinter for easy file selection, analysis, and result viewing.
*   **Robust Error Handling:** Includes comprehensive error handling and logging to provide informative feedback to the user.
* **Asynchronous Processing:** Leverages threads and concurrent processing, to improve analysis speed.
* **Cancellable Analysis:** User can stop a long-running analysis.
* **Progress Bar** Displays progress to the user.
* **Modern UI:** Provides a clean and modern UI.

## Dependencies

*   **Python 3.7+:**  The script is written in Python 3.
*   **pyshark:**  For PCAP file analysis.  Install with:  `pip install pyshark`
*   **requests:** For interacting with the AbuseIPDB API. Install with: `pip install requests`
*   **ipaddress:**  Included in the Python standard library (for IP address validation).

**Note**: TShark (part of Wireshark) must be installed and in your system's PATH for `pyshark` to work.  You likely already have this if you have Wireshark installed.  If not, download and install Wireshark from [https://www.wireshark.org/](https://www.wireshark.org/).

## Installation

1.  **Clone the repository (or download the Python script):**

    ```bash
    git clone <repository_url>  # Replace <repository_url>
    cd <repository_directory>
    ```

    (If you don't have git, simply download the `traffic_analyzer.py` file.)

2.  **Install dependencies:**

    ```bash
    pip install pyshark requests
    ```

3.  **Ensure Wireshark/TShark is installed:**  See the "Dependencies" section above.

## Usage

1.  **Run the script:**

    ```bash
    python traffic_analyzer.py
    ```

2.  **GUI Instructions:**

    *   **PCAP File:** Click "Browse" to select the PCAP or PCAPNG file you want to analyze.
    *   **Alerts File (Optional):** Click "Browse" to select an alert file (e.g., Suricata's `alerts.log`, Zeek's `conn.log`).  This is optional but highly recommended for correlation.
    *   **AbuseIPDB API Key (Optional):**  Enter your AbuseIPDB API key if you want to check the reputation of the identified infected IP address.  Get a free key from [https://www.abuseipdb.com/](https://www.abuseipdb.com/).  This is optional.
    *   **Run Analysis:** Click the "Run Analysis" button to start the analysis.  A progress bar will indicate activity.
    *   **Cancel:** Click "Cancel" to stop a running analysis.
    *   **View Results:** The analysis results will be displayed in the text area below the buttons.
    *   **Export Results:** Click "Export Results" to save the results to a JSON file.  You'll be prompted to choose a file location.

## Example Workflow

1.  You receive an alert from your intrusion detection system (IDS) indicating suspicious activity.
2.  You capture network traffic (a PCAP file) around the time of the alert.
3.  You have the IDS alert file (e.g., `fast.log` from Suricata).
4.  Run the `traffic_analyzer.py` script.
5.  Select the PCAP file and the alert file in the GUI.
6.  (Optional) Enter your AbuseIPDB API key.
7.  Click "Run Analysis".
8.  Review the results to identify the infected host, malicious URLs, file hashes, and other relevant information.
9.  Export the results to a JSON file for documentation or further analysis.

## Limitations and Considerations

*   **Hostname and User Account Extraction:**  The accuracy of hostname and user account extraction depends on the presence of specific network protocols (DNS, NBNS, DHCP, SMB) and the format of the data within those protocols.  It may not always be possible to determine these values.
*   **Executable Hash Calculation:**  The tool attempts to extract and hash potential executable payloads.  It relies on identifying TCP data streams and may not be 100% accurate.  False positives are possible.  It's best used in conjunction with other analysis techniques.
*   **AbuseIPDB API:**  The free AbuseIPDB API has rate limits.  If you exceed these limits, the IP reputation check may fail.
*   **Large PCAP Files:**  Analyzing very large PCAP files can take a significant amount of time.
* **Zeek/Suricata Versions:** While the script is designed to work with the common output formats, slight changes to output formatting in future versions of Zeek or Suricata *could* cause parsing issues.

## Contributing

Contributions are welcome!  If you find bugs or have suggestions for improvements, please open an issue or submit a pull request.
