import pandas as pd
from scapy.all import IP, TCP, UDP, ICMP
from .utils import get_service, get_tcp_flag_str

# Define the 41 column names expected by the preprocessor/model (derived from NSL-KDD)
KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

# Features that are hard/impossible to get reliably from single packets without state/deep inspection
DEFAULT_ZERO_FEATURES = [
    "duration", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

def extract_features_from_packet(packet):
    """
    Extracts KDD-like features from a single Scapy packet.
    Returns a dictionary of features or None if not IP layer.
    NOTE: This is an APPROXIMATION. Many KDD features require connection state.
    """
    if not packet.haslayer(IP):
        return None # We need IP layer for src/dst addresses

    features = {col: 0 for col in KDD_COLUMNS} # Initialize with defaults

    ip_layer = packet.getlayer(IP)
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = ip_layer.proto

    # Basic Features
    # Scapy packets might not have sport/dport if not TCP/UDP layer
    src_port = packet.sport if hasattr(packet, 'sport') else 0
    dst_port = packet.dport if hasattr(packet, 'dport') else 0
    features['land'] = 1 if src_ip == dst_ip and src_port == dst_port and src_port != 0 else 0
    features['src_bytes'] = len(ip_layer.payload) # Approximating with payload length
    features['dst_bytes'] = 0 # Can't know dst_bytes from a single packet reliably

    # Protocol Specific Features
    if protocol == 6 and packet.haslayer(TCP): # TCP
        tcp_layer = packet.getlayer(TCP)
        features['protocol_type'] = 'tcp'
        features['service'] = get_service(tcp_layer.dport, 'tcp')
        features['flag'] = get_tcp_flag_str(tcp_layer.flags)
        if hasattr(tcp_layer, 'load'): features['src_bytes'] = len(tcp_layer.load)
        else: features['src_bytes'] = 0

    elif protocol == 17 and packet.haslayer(UDP): # UDP
        udp_layer = packet.getlayer(UDP)
        features['protocol_type'] = 'udp'
        features['service'] = get_service(udp_layer.dport, 'udp')
        features['flag'] = 'SF'
        if hasattr(udp_layer, 'load'): features['src_bytes'] = len(udp_layer.load)
        else: features['src_bytes'] = 0

    elif protocol == 1 and packet.haslayer(ICMP): # ICMP
        icmp_layer = packet.getlayer(ICMP)
        features['protocol_type'] = 'icmp'
        features['service'] = get_service(icmp_layer.type, 'icmp')
        features['flag'] = 'SF'
        if hasattr(icmp_layer, 'load'): features['src_bytes'] = len(icmp_layer.load)
        else: features['src_bytes'] = 0
    else: # Other protocols
        features['protocol_type'] = 'other'
        features['service'] = 'other'
        features['flag'] = 'OTH'
        features['src_bytes'] = len(ip_layer.payload)

    # Fill remaining default features
    for feat in DEFAULT_ZERO_FEATURES:
        if feat not in ['src_bytes', 'dst_bytes', 'land', 'protocol_type', 'service', 'flag']:
             features[feat] = 0

    # Add packet metadata
    features['_packet_time'] = float(packet.time)
    features['_src_ip'] = src_ip
    features['_dst_ip'] = dst_ip
    features['_src_port'] = src_port
    features['_dst_port'] = dst_port

    return features 