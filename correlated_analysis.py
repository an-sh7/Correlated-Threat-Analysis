import pyshark
import hashlib
import re
import ipaddress

# Paths to the input files
pcap_file = "2019-02-23-traffic-analysis-exercise.pcap"
alerts_file = "2019-02-23-traffic-analysis-exercise-alerts.txt"

def is_private_ip(ip):
    """Check if an IP address is within a private range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def parse_alerts():
    """
    Parse the IDS alerts file to:
      - Count how many times each IP appears (source and destination).
      - Collect potential malicious/external IPs.
      - Extract executable URLs from lines that indicate Windows executable downloads.
    Then determine the infected (internal) host by selecting the private IP with the highest count.
    """
    ip_counts = {}
    malicious_ips = set()
    exe_urls = set()

    with open(alerts_file, "r") as f:
        for line in f:
            # Look for lines with "A.B.C.D -> E.F.G.H"
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                src_ip, dst_ip = ip_match.groups()
                # Count each occurrence for both source and destination
                ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1

                # Mark source IP as malicious (external attackers)
                malicious_ips.add(src_ip)

                # If the alert indicates an executable download, try to extract a URL
                if "ET MALWARE Windows executable" in line or "EXE download" in line:
                    url_match = re.search(r'(https?://[^\s]+)', line)
                    if url_match:
                        exe_urls.add(url_match.group(1))

    # Choose the infected host: prefer the private IP with the highest occurrence
    infected_ip = None
    private_ips = {ip: count for ip, count in ip_counts.items() if is_private_ip(ip)}
    if private_ips:
        infected_ip = max(private_ips, key=private_ips.get)
    elif ip_counts:
        # Fallback: choose the IP with the highest overall occurrence
        infected_ip = max(ip_counts, key=ip_counts.get)

    return infected_ip, malicious_ips, exe_urls

# Parse alerts and determine indicators
infected_ip, malicious_ips, exe_urls = parse_alerts()

if not infected_ip:
    print("❌ No infected host IP could be determined from alerts.")
    exit()

# Open the PCAP file and filter only packets related to the infected host
cap = pyshark.FileCapture(pcap_file, display_filter=f"ip.addr == {infected_ip}")

infected_mac = None
hostname = None
user_account = None
exe_hashes = set()

try:
    for packet in cap:
        try:
            # Retrieve the first seen MAC address for the infected host
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

            # If an HTTP packet contains a full URI (which might indicate an executable download), add it to the list
            if hasattr(packet, "http") and hasattr(packet.http, "request_full_uri"):
                exe_urls.add(packet.http.request_full_uri)

            # For file transfers: if the packet has TCP data, try to compute a SHA256 hash
            if hasattr(packet, "tcp") and hasattr(packet, "data"):
                hex_data = packet.data.data.replace(":", "")  # Remove any colons from hex data
                try:
                    data_payload = bytes.fromhex(hex_data)
                    sha256_hash = hashlib.sha256(data_payload).hexdigest()
                    exe_hashes.add(sha256_hash)
                except ValueError:
                    # Skip packets that fail hex conversion
                    pass

        except Exception:
            # If a packet cannot be processed, skip it and continue
            continue
finally:
    cap.close()

# Display the results of the correlation analysis
print("\n🚨 **Correlated Threat Analysis** 🚨\n")
print(f"Infected Windows Host IP: {infected_ip}")
print(f"Infected Windows Host MAC: {infected_mac if infected_mac else 'Not Found'}")
print(f"Host Name: {hostname if hostname else 'Not Found (Check NBNS/DHCP in Wireshark)'}")
print(f"Windows User Account Name: {user_account if user_account else 'Not Found (Check SMB packets)'}")
print(f"Malicious URLs serving executables: {list(exe_urls)[:6]}")
print(f"SHA256 hashes of the executables: {list(exe_hashes)[:6]}")
print(f"Malicious External IPs: {list(malicious_ips)}")
