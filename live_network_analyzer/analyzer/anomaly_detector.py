from collections import defaultdict
import time
import ipaddress
import socket

# --- Configuration ---
TIME_WINDOW = 3  # Keep at 3 seconds for detection window
SYN_FLOOD_THRESHOLD = 5  # Lower from 20 to 5 SYNs to detect smaller attacks
PORT_SCAN_THRESHOLD = 5  # Lower from 10 to 5 different ports

# --- State Variables (In-memory - reset on restart) ---
syn_counts = defaultdict(lambda: {'count': 0, 'timestamp': 0})
connection_attempts = defaultdict(lambda: {'ports': set(), 'timestamp': 0})
alerts = [] # Global list to store alerts across batches

# Track local IP addresses for better attack attribution
LOCAL_IP_CACHE = None

def get_local_ips():
    """Get all local IP addresses for better attack attribution"""
    global LOCAL_IP_CACHE
    if LOCAL_IP_CACHE is not None:
        return LOCAL_IP_CACHE
        
    local_ips = set()
    try:
        # Get hostname and local IP
        hostname = socket.gethostname()
        local_ips.add(socket.gethostbyname(hostname))
        
        # Try to get all addresses
        addresses = socket.getaddrinfo(hostname, None)
        for addr in addresses:
            local_ips.add(addr[4][0])
    except Exception as e:
        print(f"Error getting local IPs: {e}")
    
    # Add loopback addresses
    local_ips.add('127.0.0.1')
    local_ips.add('::1')
    
    LOCAL_IP_CACHE = local_ips
    print(f"Local IPs detected: {local_ips}")
    return local_ips

def is_private_ip(ip_str):
    """Check if an IP address is in private IP space"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False

def is_local_ip(ip_str):
    """Check if IP is one of our local machine's IPs"""
    return ip_str in get_local_ips()

def _clear_old_state(current_time):
    """ Remove entries older than the time window, but keep current data longer """
    global syn_counts, connection_attempts
    old_syn_count = len(syn_counts)
    old_conn_count = len(connection_attempts)
    
    # Use a longer expiration window for state tracking (twice the normal window)
    extended_window = TIME_WINDOW * 2
    
    syn_counts = defaultdict(lambda: {'count': 0, 'timestamp': 0},
                           {ip: data for ip, data in syn_counts.items()
                            if current_time - data['timestamp'] < extended_window})
    connection_attempts = defaultdict(lambda: {'ports': set(), 'timestamp': 0},
                                     {ip: data for ip, data in connection_attempts.items()
                                      if current_time - data['timestamp'] < extended_window})
    
    if old_syn_count != len(syn_counts) or old_conn_count != len(connection_attempts):
        print(f"State cleanup: SYN states {old_syn_count}->{len(syn_counts)}, Connection states {old_conn_count}->{len(connection_attempts)}")

def check_anomalies(packet_features_df):
    """
    Analyzes a DataFrame of extracted packet features for rule-based anomalies.
    Updates global state and returns a list of NEW alerts generated in this batch.
    """
    global alerts, syn_counts, connection_attempts
    new_alerts_in_batch = []
    current_time = time.time()
    _clear_old_state(current_time)

    if packet_features_df is None or packet_features_df.empty:
        return new_alerts_in_batch

    print(f"\nProcessing batch of {len(packet_features_df)} packets for anomalies...")

    # Print unique flag values for debugging
    if not packet_features_df.empty and 'flag' in packet_features_df.columns:
        flag_counts = packet_features_df['flag'].value_counts().to_dict()
        print(f"TCP Flags in batch: {flag_counts}")
        
        # Check for S0 flags specifically
        if 'S0' in flag_counts:
            print(f"Found {flag_counts['S0']} SYN packets in this batch")

    # Track SYN packets by destination IP to identify targets of SYN floods
    dst_syn_counts = defaultdict(int)
    
    # Get local IPs for better attack attribution
    local_ips = get_local_ips()
    
    for index, row in packet_features_df.iterrows():
        timestamp = row.get('_packet_time', current_time)
        src_ip = row.get('_src_ip')
        dst_ip = row.get('_dst_ip')
        dst_port = row.get('_dst_port')
        protocol = row.get('protocol_type')
        flag = row.get('flag')

        if not src_ip:
            print(f"Warning: Packet at index {index} has no source IP")
            continue
            
        # Check if this is traffic to/from our own machine
        src_is_local = is_local_ip(src_ip)
        dst_is_local = is_local_ip(dst_ip)
        
        # We want to detect:
        # 1. External IPs attacking us (src=external, dst=local)
        # 2. Local network devices attacking each other (src=private, dst=private, neither is local)
        # We want to ignore:
        # 1. Our own outbound connections (src=local, dst=external)

        # --- SYN Flood Detection ---
        if protocol == 'tcp' and flag == 'S0':
            print(f"TCP SYN: {src_ip}->{dst_ip}:{dst_port}")
            
            # Track count by destination IP (target of the attack)
            dst_syn_counts[dst_ip] += 1
            
            # For proper attack attribution, we need to determine the actual attacker
            attacker_ip = src_ip
            victim_ip = dst_ip
            
            # Ignore our own outbound SYN packets to prevent false positives
            if src_is_local and not dst_is_local:
                print(f"Outbound SYN from local IP {src_ip} to external {dst_ip} - ignoring")
                continue
                
            # Always track all SYN packets by source
            if current_time - syn_counts[attacker_ip]['timestamp'] >= TIME_WINDOW:
                syn_counts[attacker_ip]['count'] = 0
            syn_counts[attacker_ip]['count'] += 1
            syn_counts[attacker_ip]['timestamp'] = current_time
            
            print(f"SYN count for {attacker_ip}: {syn_counts[attacker_ip]['count']}/{SYN_FLOOD_THRESHOLD}")

            # Check for SYN flood threshold 
            if syn_counts[attacker_ip]['count'] >= SYN_FLOOD_THRESHOLD:
                alert_msg = f"⚠️ SYN Flood Attack detected from {attacker_ip} to {victim_ip} ({syn_counts[attacker_ip]['count']} SYNs in {TIME_WINDOW}s)"
                if alert_msg not in alerts:
                    print(f"\n!!! ALERT (Rule): {alert_msg}")
                    alerts.append(alert_msg)
                    new_alerts_in_batch.append(alert_msg)
                    print(f"Added SYN flood alert to batch. Total alerts now: {len(alerts)}")

        # --- Port Scan Detection (Basic) ---
        if protocol in ['tcp', 'udp']:
            # Skip tracking outbound connections from our machine to reduce false positives
            if src_is_local and not dst_is_local:
                continue
                
            # Track connections by source IP
            if current_time - connection_attempts[src_ip]['timestamp'] >= TIME_WINDOW:
                connection_attempts[src_ip]['ports'] = set()
            connection_attempts[src_ip]['ports'].add((dst_ip, dst_port))  # Track IP:port pairs
            connection_attempts[src_ip]['timestamp'] = current_time
            
            # Get unique destination ports
            unique_ports = set(port for _, port in connection_attempts[src_ip]['ports'])
            port_count = len(unique_ports)
            
            # Only print port counts if they're getting close to threshold
            if port_count > PORT_SCAN_THRESHOLD // 2:
                print(f"Port count for {src_ip}: {port_count}/{PORT_SCAN_THRESHOLD}")
                
            if port_count >= PORT_SCAN_THRESHOLD:
                alert_msg = f"🔍 Port Scan detected from {src_ip} to {dst_ip} ({port_count} ports in {TIME_WINDOW}s)"
                if alert_msg not in alerts:
                    print(f"\n!!! ALERT (Rule): {alert_msg}")
                    alerts.append(alert_msg)
                    new_alerts_in_batch.append(alert_msg)
                    print(f"Added port scan alert to batch. Total alerts now: {len(alerts)}")

        # --- ICMP Flood Detection ---
        if protocol == 'icmp':
            print(f"ICMP: {src_ip}->{dst_ip}")
            
            # We could implement ICMP flood detection here if needed
            # This would be similar to SYN flood but tracking ICMP packets
            
    # Check for targeted IPs receiving many SYN packets
    for dst_ip, count in dst_syn_counts.items():
        if count >= SYN_FLOOD_THRESHOLD:
            print(f"Potential attack target detected: {dst_ip} received {count} SYN packets")
            if is_local_ip(dst_ip):
                print(f"Attack targeting local machine {dst_ip}!")

    if new_alerts_in_batch:
        print(f"\nNew alerts in this batch: {len(new_alerts_in_batch)}")
        for alert in new_alerts_in_batch:
            print(f"  - {alert}")
    else:
        print(f"No new alerts found in this batch.")

    # Print overall state
    print(f"Current state: {len(syn_counts)} SYN trackers, {len(connection_attempts)} connection trackers, {len(alerts)} total alerts")
    
    return new_alerts_in_batch

def get_all_alerts():
    """ Returns the list of all unique alerts generated so far. """
    return list(alerts)

def clear_all_rule_state():
    """ Clears the alert list AND the detection state. """
    global alerts, syn_counts, connection_attempts, LOCAL_IP_CACHE
    alerts = []
    syn_counts = defaultdict(lambda: {'count': 0, 'timestamp': 0})
    connection_attempts = defaultdict(lambda: {'ports': set(), 'timestamp': 0})
    LOCAL_IP_CACHE = None
    print("Cleared all anomaly detection state and alerts.") 