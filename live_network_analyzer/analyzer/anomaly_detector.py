from collections import defaultdict
import time

# --- Configuration ---
TIME_WINDOW = 10  # seconds for rate limiting checks
SYN_FLOOD_THRESHOLD = 100  # SYNs per IP in window
PORT_SCAN_THRESHOLD = 20   # Different destination ports per IP in window

# --- State Variables (In-memory - reset on restart) ---
syn_counts = defaultdict(lambda: {'count': 0, 'timestamp': 0})
connection_attempts = defaultdict(lambda: {'ports': set(), 'timestamp': 0})
alerts = [] # Global list to store alerts across batches

def _clear_old_state(current_time):
    """ Remove entries older than the time window """
    global syn_counts, connection_attempts
    syn_counts = defaultdict(lambda: {'count': 0, 'timestamp': 0},
                           {ip: data for ip, data in syn_counts.items()
                            if current_time - data['timestamp'] < TIME_WINDOW})
    connection_attempts = defaultdict(lambda: {'ports': set(), 'timestamp': 0},
                                     {ip: data for ip, data in connection_attempts.items()
                                      if current_time - data['timestamp'] < TIME_WINDOW})

def check_anomalies(packet_features_df):
    """
    Analyzes a DataFrame of extracted packet features for rule-based anomalies.
    Updates global state and returns a list of NEW alerts generated in this batch.
    """
    global alerts
    new_alerts_in_batch = [] # Track only alerts found in this specific call
    current_time = time.time()
    _clear_old_state(current_time)

    if packet_features_df is None or packet_features_df.empty:
        return new_alerts_in_batch

    for index, row in packet_features_df.iterrows():
        timestamp = row.get('_packet_time', current_time)
        src_ip = row.get('_src_ip')
        dst_ip = row.get('_dst_ip')
        dst_port = row.get('_dst_port')
        protocol = row.get('protocol_type')
        flag = row.get('flag')

        if not src_ip: continue

        # --- SYN Flood Detection ---
        if protocol == 'tcp' and flag == 'S0':
            if current_time - syn_counts[src_ip]['timestamp'] >= TIME_WINDOW:
                 syn_counts[src_ip]['count'] = 0
            syn_counts[src_ip]['count'] += 1
            syn_counts[src_ip]['timestamp'] = current_time

            if syn_counts[src_ip]['count'] > SYN_FLOOD_THRESHOLD:
                alert_msg = f"Potential SYN Flood detected from {src_ip} ({syn_counts[src_ip]['count']} SYNs in last {TIME_WINDOW}s)"
                # Add to global list only if truly new overall
                if alert_msg not in alerts:
                    print(f"ALERT (Rule): {alert_msg}")
                    alerts.append(alert_msg)
                    new_alerts_in_batch.append(alert_msg) # Also add to batch list

        # --- Port Scan Detection (Basic) ---
        if protocol == 'tcp' or protocol == 'udp':
            if current_time - connection_attempts[src_ip]['timestamp'] >= TIME_WINDOW:
                connection_attempts[src_ip]['ports'] = set()
            connection_attempts[src_ip]['ports'].add(dst_port)
            connection_attempts[src_ip]['timestamp'] = current_time

            if len(connection_attempts[src_ip]['ports']) > PORT_SCAN_THRESHOLD:
                 alert_msg = f"Potential Port Scan detected from {src_ip} ({len(connection_attempts[src_ip]['ports'])} ports in last {TIME_WINDOW}s)"
                 if alert_msg not in alerts:
                     print(f"ALERT (Rule): {alert_msg}")
                     alerts.append(alert_msg)
                     new_alerts_in_batch.append(alert_msg)

    return new_alerts_in_batch # Return only the alerts found now

def get_all_alerts():
    """ Returns the list of all unique alerts generated so far. """
    return list(alerts) # Return a copy

def clear_all_rule_state():
    """ Clears the alert list AND the detection state. """
    global alerts, syn_counts, connection_attempts
    alerts = []
    syn_counts = defaultdict(lambda: {'count': 0, 'timestamp': 0})
    connection_attempts = defaultdict(lambda: {'ports': set(), 'timestamp': 0})
    print("Cleared all anomaly detection state and alerts.") 