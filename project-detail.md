creating a live packet capturing application with a native Windows GUI is a significant step up in complexity, primarily due to:

1.  **Live Capture Permissions:** Capturing network traffic requires elevated (Administrator) privileges on Windows.
2.  **GUI Framework:** We need to switch from Flask (web) to a desktop GUI toolkit like Tkinter, PyQt, Kivy, or CustomTkinter. We'll use **CustomTkinter** as it provides modern styling over standard Tkinter and is relatively easy to set up.
3.  **Threading:** Live packet sniffing is a blocking operation. It *must* run in a separate thread to avoid freezing the GUI. Communication between the capture thread and the GUI thread needs to be handled carefully (using queues).
4.  **Real-time Processing:** Analyzing packets as they arrive requires efficient feature extraction and prediction.

**Let's restructure the project:**

---

### 1. Updated Folder Structure

```
live_network_analyzer/
├── main_gui.py             # Main CustomTkinter application file
├── requirements.txt        # Updated Python dependencies
├── analyzer/               # Core analysis logic (mostly reused)
│   ├── __init__.py
│   ├── packet_parser.py    # Extracts features (minor changes possible)
│   ├── predictor.py        # Loads models and predicts (reused)
│   ├── anomaly_detector.py # Rule-based detection (reused, maybe state clearing adjusted)
│   └── utils.py            # Helper functions (reused)
├── capture_thread.py       # Handles live packet capture in a separate thread
├── models/                 # <<< PLACE YOUR TRAINED MODELS HERE >>>
│   ├── dnn_model.h5
│   ├── dnn_preprocessor.joblib
│   └── apriori_rule.pkl
└── README.md               # Updated instructions
```

---

### 2. Updated `requirements.txt`

```txt
# requirements.txt
customtkinter>=5.2.0 # GUI Toolkit
pandas>=1.3
numpy>=1.20
scikit-learn>=1.0
tensorflow>=2.8 # Ensure compatibility with your saved model
mlxtend>=0.19
joblib>=1.1
scapy>=2.4
# Werkzeug is not needed anymore (Flask dependency)
# python-dotenv optional
```

---

### 3. Code for New/Modified Files

**`analyzer/packet_parser.py` (Largely the same, ensure KDD_COLUMNS is defined)**

```python
# analyzer/packet_parser.py
# (Keep the code from the previous response, ensuring KDD_COLUMNS,
# DEFAULT_ZERO_FEATURES, extract_features_from_packet are defined)
# We will primarily use extract_features_from_packet

import pandas as pd
from scapy.all import IP, TCP, UDP, ICMP # No need for rdpcap here
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

# process_pcap function is no longer needed for live capture mode
```

**`analyzer/predictor.py` (Identical to previous response)**

```python
# analyzer/predictor.py
# (Keep the exact code from the previous Flask example)
# It loads models and performs prediction on a DataFrame
import tensorflow as tf
import joblib
import pickle
import pandas as pd
import numpy as np
import os

# Define features needed for Apriori rule matching (must match training)
DISCRETE_FEATURES_APRIORI = [
    'protocol_type', 'service', 'flag', 'land', 'logged_in',
    'root_shell', 'su_attempted', 'is_host_login', 'is_guest_login'
]

# KDD columns (needed to ensure correct order for the preprocessor)
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

class TrafficPredictor:
    def __init__(self, model_dir="models"):
        self.model_path = os.path.join(model_dir, "dnn_model.h5")
        self.preprocessor_path = os.path.join(model_dir, "dnn_preprocessor.joblib")
        self.rule_path = os.path.join(model_dir, "apriori_rule.pkl")
        self.model = None
        self.preprocessor = None
        self.apriori_rule_antecedents = None
        self._load_artifacts()

    def _load_artifacts(self):
        """ Loads the trained model, preprocessor, and Apriori rule. """
        print("Loading prediction artifacts...")
        try:
            self.model = tf.keras.models.load_model(self.model_path, compile=False)
            print(f"Loaded DNN model from {self.model_path}")
        except Exception as e:
            print(f"Error loading DNN model: {e}")
            raise

        try:
            self.preprocessor = joblib.load(self.preprocessor_path)
            print(f"Loaded DNN preprocessor from {self.preprocessor_path}")
        except Exception as e:
            print(f"Error loading preprocessor: {e}")
            raise

        try:
            with open(self.rule_path, 'rb') as f:
                self.apriori_rule_antecedents = pickle.load(f)
            print(f"Loaded Apriori rule from {self.rule_path}")
            print(f"  Rule Antecedents: {self.apriori_rule_antecedents}")
        except Exception as e:
            print(f"Error loading Apriori rule: {e}")
            raise
        print("Prediction artifacts loaded successfully.")


    def predict_traffic(self, features_df, threshold=0.5):
        """
        Predicts traffic using DNN and applies Apriori filtering.
        Assumes features_df contains the KDD_COLUMNS + metadata.
        Returns predictions (0=Normal, 1=Attack) as a numpy array.
        """
        if self.model is None or self.preprocessor is None or self.apriori_rule_antecedents is None:
            print("Error: Models/Preprocessor/Rule not loaded. Cannot predict.")
            return None

        if features_df.empty:
            # print("Received empty DataFrame for prediction.") # Too noisy for live
            return np.array([])

        # print(f"Predicting on {len(features_df)} samples...") # Too noisy

        # 1. Prepare data for Apriori matching
        apriori_match_data = pd.DataFrame()
        for col in DISCRETE_FEATURES_APRIORI:
            if col in features_df.columns:
                 apriori_match_data[col] = col + '=' + features_df[col].astype(str)
            # else: # Don't warn repeatedly in live mode
                 # print(f"Warning: Discrete feature '{col}' not found...")

        apriori_sets = apriori_match_data.apply(lambda row: set(row.dropna()), axis=1).tolist()


        # 2. Prepare data for DNN prediction
        try:
            dnn_input_df = features_df[KDD_COLUMNS].copy()
        except KeyError as e:
             print(f"Error: Missing required KDD column in input DataFrame: {e}")
             return None

        # Preprocess using the loaded preprocessor
        try:
            X_processed = self.preprocessor.transform(dnn_input_df)
            # print(f"Data preprocessed for DNN. Shape: {X_processed.shape}") # Too noisy
        except Exception as e:
             print(f"Error during preprocessing: {e}")
             return None

        # 3. Make initial DNN predictions
        dnn_predictions_prob = self.model.predict(X_processed, verbose=0) # verbose=0 for less console noise
        dnn_predictions = (dnn_predictions_prob > threshold).astype(int).flatten()
        # print(f"Initial DNN predictions count (Attack=1): {np.sum(dnn_predictions)}") # Too noisy

        # 4. Apply Apriori Filtering
        final_predictions = dnn_predictions.copy()
        filtered_count = 0
        attack_indices = np.where(dnn_predictions == 1)[0]

        if not isinstance(self.apriori_rule_antecedents, (set, frozenset)) or len(self.apriori_rule_antecedents) == 0:
             # print(f"Warning: Invalid/Empty Apriori rule. Skipping filtering.") # Too noisy
             pass # Just don't filter
        else:
            # print(f"Applying Apriori filter...") # Too noisy
            if len(apriori_sets) == len(final_predictions):
                for i, idx in enumerate(attack_indices):
                    if self.apriori_rule_antecedents.issubset(apriori_sets[idx]):
                        final_predictions[idx] = 0
                        filtered_count += 1
            # else: # Too noisy
                 # print(f"Warning: Mismatch between Apriori data and predictions. Skipping filtering.")

        # if filtered_count > 0: print(f"Apriori filtered {filtered_count} predictions.") # Too noisy
        # print(f"Final predictions count (Attack=1): {np.sum(final_predictions)}") # Too noisy

        return final_predictions
```

**`analyzer/anomaly_detector.py` (Identical to previous response)**

```python
# analyzer/anomaly_detector.py
# (Keep the exact code from the previous Flask example)
# Includes TIME_WINDOW, thresholds, state dicts, check_anomalies, get_all_alerts, clear_alerts
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

    # print(f"Checking {len(packet_features_df)} packets for anomalies...") # Too noisy

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

    # print(f"Anomaly check complete. Found {len(new_alerts_in_batch)} new alerts in batch.") # Too noisy
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

```

**`analyzer/utils.py` (Identical to previous response)**

```python
# analyzer/utils.py
# (Keep the exact code from the previous Flask example)
# Includes SERVICE_MAP, get_tcp_flag_str, get_service, etc.
import datetime
import ipaddress

# Basic service mapping (extend as needed)
SERVICE_MAP = {
    # TCP
    7: 'echo', 20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
    53: 'domain', 67: 'bootps', 68: 'bootpc', 69: 'tftp', 80: 'http', 88: 'kerberos',
    110: 'pop3', 113: 'auth', 119: 'nntp', 123: 'ntp', 135: 'msrpc', 137: 'netbios_ns',
    138: 'netbios_dgm', 139: 'netbios_ssn', 143: 'imap4', 161: 'snmp', 162: 'snmptrap',
    179: 'bgp', 194: 'irc', 389: 'ldap', 443: 'https', 445: 'microsoft-ds', 465: 'smtps',
    514: 'syslog', 543: 'klogin', 544: 'kshell', 587: 'submission', 636: 'ldaps',
    993: 'imaps', 995: 'pop3s', 8000: 'http_alt', 8080: 'http_proxy',
    # UDP
    5060: 'sip',
    # Others
    1: 'icmp', 10: 'private',
}

def get_tcp_flag_str(flags):
    if flags.R: return 'REJ'
    elif flags.S and not flags.A: return 'S0'
    elif flags.F: return 'SH' # Simplification
    elif flags.S and flags.A: return 'S1' # Simplification
    elif flags.A and not flags.S and not flags.F and not flags.R: return 'SF' # Optimistic guess
    else: return 'OTH'

def get_service(dport, protocol_name):
    if protocol_name == 'icmp': return 'icmp'
    service = SERVICE_MAP.get(dport)
    if service: return service
    elif 1024 <= dport <= 49151: return 'private'
    else: return 'other'

def is_private_ip(ip_addr):
    if not ip_addr: return False
    try: return ipaddress.ip_address(ip_addr).is_private
    except ValueError: return False

def get_current_timestamp():
    return datetime.datetime.now().timestamp()
```

**`capture_thread.py` (New File)**

```python
# capture_thread.py
import threading
import queue
from scapy.all import sniff, conf as scapy_conf, get_windows_if_list, Lfilter
import platform

# Filter to ignore packets likely related to the capture machine itself (optional)
# Adjust the IP address if needed
# MY_IP = "192.168.1.100" # Example: Replace with a way to get local IP if desired
# class MyIPFilter(Lfilter):
#     def __call__(self, pkt):
#         return not (pkt.haslayer(IP) and (pkt[IP].src == MY_IP or pkt[IP].dst == MY_IP))

class CaptureThread(threading.Thread):
    def __init__(self, packet_queue, interface_name=None, packet_count=0, stop_timeout=1):
        """
        Initializes the capture thread.
        :param packet_queue: A queue.Queue to put captured packets into.
        :param interface_name: The name/GUID of the interface to sniff on (required for Windows).
        :param packet_count: Number of packets to capture (0 for indefinite).
        :param stop_timeout: How often sniff checks the stop event (seconds).
        """
        super().__init__(daemon=True) # Daemon threads exit when the main program exits
        self.packet_queue = packet_queue
        self.interface_name = interface_name
        self.packet_count = packet_count
        self.stop_timeout = stop_timeout
        self.stop_event = threading.Event()
        self.sniffer = None # To hold the Scapy sniffer instance

    def _packet_callback(self, packet):
        """ Called by Scapy for each captured packet. Puts packet in queue. """
        if packet:
            # Note: Putting the raw Scapy packet object might consume memory quickly
            # Consider extracting features here if performance is an issue,
            # but that tightly couples capture and parsing.
            self.packet_queue.put(packet)

    def run(self):
        """ Starts the packet capture process. """
        print(f"Capture thread started on interface: {self.interface_name}")
        self.stop_event.clear()
        try:
            # Use Lfilter to potentially exclude local machine traffic if desired
            # lfilter = MyIPFilter()
            self.sniffer = sniff(
                iface=self.interface_name,       # Interface name (GUID on Windows)
                prn=self._packet_callback,       # Function to call for each packet
                count=self.packet_count,         # 0 for continuous capture
                store=False,                     # Do not store packets in memory here
                stop_filter=lambda p: self.stop_event.is_set(), # Check stop event
                timeout=self.stop_timeout        # Timeout for stop_filter check
                # lfilter=lfilter                # Optional filter
            )
        except OSError as e:
             # Handle potential permission errors or invalid interface
             print(f"ERROR starting capture on {self.interface_name}: {e}")
             print("-> Ensure Npcap is installed and the script is run as Administrator.")
             # Optionally signal an error back to the main thread via the queue or another mechanism
             self.packet_queue.put("CAPTURE_ERROR") # Signal error
        except Exception as e:
            print(f"An unexpected error occurred during capture: {e}")
            self.packet_queue.put("CAPTURE_ERROR") # Signal error
        finally:
            print(f"Capture thread finished on interface: {self.interface_name}")
            self.packet_queue.put("CAPTURE_FINISHED") # Signal completion

    def stop(self):
        """ Signals the capture thread to stop. """
        print("Signaling capture thread to stop...")
        self.stop_event.set()
        # Note: sniff() might take up to stop_timeout seconds to actually stop


def get_interfaces():
    """ Gets a list of network interfaces suitable for display. """
    interfaces = []
    print("Fetching network interfaces...")
    try:
        if platform.system() == "Windows":
            # get_windows_if_list returns dicts with 'name', 'guid', 'description', etc.
            # We need the 'name' or 'description' for display, but the 'guid' or index for sniffing
            # Let's try to create a user-friendly name and store the identifier needed by sniff
            ifs = get_windows_if_list()
            # print("Raw Windows Interfaces:", ifs) # Debugging
            for iface_dict in ifs:
                 # Use description if available, otherwise name
                 display_name = iface_dict.get('description', iface_dict.get('name', 'Unknown'))
                 # Scapy's iface parameter on Windows often needs the 'name' field from this list
                 # which might look like 'Ethernet', 'Wi-Fi', or a GUID. Let's use 'name'.
                 sniff_id = iface_dict.get('name')
                 if display_name and sniff_id:
                     interfaces.append({"display": f"{display_name} ({sniff_id})", "id": sniff_id})

        else: # Linux/macOS (Untested with this specific GUI structure)
             # On Linux/macOS, scapy_conf.ifaces usually works
             # The keys are the names sniff expects (e.g., 'eth0', 'en0')
             ifaces = scapy_conf.ifaces.data
             for name, iface_data in ifaces.items():
                  # Try to get a description or IP address for better display name
                  ip = iface_data.ip if hasattr(iface_data, 'ip') else 'No IP'
                  display_name = f"{name} ({ip})"
                  interfaces.append({"display": display_name, "id": name})

    except Exception as e:
        print(f"Error getting interfaces: {e}")
        # Provide a dummy entry or handle the error appropriately in the GUI
        interfaces.append({"display": "Error fetching interfaces", "id": None})

    if not interfaces:
         interfaces.append({"display": "No interfaces found", "id": None})

    print(f"Found interfaces: {[iface['display'] for iface in interfaces]}")
    return interfaces

```

**`main_gui.py` (New File - Main Application)**

```python
# main_gui.py
import customtkinter as ctk
from tkinter import ttk # For Treeview
import queue
import threading
import time
import platform
import pandas as pd
from collections import deque

# Analyzer components
from analyzer.packet_parser import extract_features_from_packet, KDD_COLUMNS
from analyzer.predictor import TrafficPredictor
from analyzer.anomaly_detector import check_anomalies, clear_all_rule_state
from analyzer.utils import get_current_timestamp # Import needed utils if any
import capture_thread # Import the capture thread logic and interface fetching

# --- Configuration ---
APP_TITLE = "Live Network Traffic Analyzer"
THEME = "System" # "System", "Dark", "Light"
MODEL_DIR = 'models'
MAX_PACKETS_IN_QUEUE = 1000 # Limit queue size to prevent memory issues
PROCESSING_INTERVAL_MS = 500 # How often to check the packet queue (milliseconds)
MAX_DISPLAY_ITEMS = 100 # Max items to keep in alerts/attacks lists in GUI

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(APP_TITLE)
        self.geometry("900x700")
        ctk.set_appearance_mode(THEME)
        ctk.set_default_color_theme("blue")

        # --- State Variables ---
        self.capture_thread = None
        self.packet_queue = queue.Queue(maxsize=MAX_PACKETS_IN_QUEUE)
        self.is_capturing = False
        self.total_packets_processed = 0
        self.model_attacks_detected = 0
        self.rule_alerts = deque(maxlen=MAX_DISPLAY_ITEMS) # Use deque for limited display
        self.attack_details = deque(maxlen=MAX_DISPLAY_ITEMS) # Use deque

        # --- Load Predictor ---
        self.predictor = None
        try:
            self.predictor = TrafficPredictor(model_dir=MODEL_DIR)
        except Exception as e:
            print(f"FATAL: Could not initialize TrafficPredictor: {e}")
            # Display error in GUI later if needed

        # --- UI Elements ---
        self.create_widgets()
        self.populate_interfaces()

        # --- Graceful Shutdown ---
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1) # Make text areas expand

        # --- Top Frame: Controls ---
        self.controls_frame = ctk.CTkFrame(self)
        self.controls_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.controls_frame.grid_columnconfigure(1, weight=1)

        self.if_label = ctk.CTkLabel(self.controls_frame, text="Select Interface:")
        self.if_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.if_combobox = ctk.CTkComboBox(self.controls_frame, state="readonly", values=["Fetching..."])
        self.if_combobox.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.start_button = ctk.CTkButton(self.controls_frame, text="Start Capture", command=self.start_capture)
        self.start_button.grid(row=0, column=2, padx=5, pady=5)

        self.stop_button = ctk.CTkButton(self.controls_frame, text="Stop Capture", command=self.stop_capture, state="disabled")
        self.stop_button.grid(row=0, column=3, padx=5, pady=5)

        # --- Middle Frame: Status & Counts ---
        self.status_frame = ctk.CTkFrame(self)
        self.status_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="ew")

        self.status_label = ctk.CTkLabel(self.status_frame, text="Status: Idle", anchor="w")
        self.status_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.packet_count_label = ctk.CTkLabel(self.status_frame, text="Packets Processed: 0", anchor="w")
        self.packet_count_label.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        self.attack_count_label = ctk.CTkLabel(self.status_frame, text="Model Attacks: 0", anchor="w")
        self.attack_count_label.grid(row=0, column=2, padx=10, pady=5, sticky="w")

        self.clear_button = ctk.CTkButton(self.status_frame, text="Clear Results", command=self.clear_results, width=100)
        self.clear_button.grid(row=0, column=3, padx=10, pady=5, sticky="e")
        self.status_frame.grid_columnconfigure(3, weight=1) # Push clear button right

        # --- Bottom Frame: Results Tabs ---
        self.results_notebook = ctk.CTkTabview(self)
        self.results_notebook.grid(row=2, column=0, padx=10, pady=0, sticky="nsew")
        self.results_notebook.add("Rule Alerts")
        self.results_notebook.add("Model Attack Details")

        # Rule Alerts Tab
        self.alerts_textbox = ctk.CTkTextbox(self.results_notebook.tab("Rule Alerts"), state="disabled", wrap="word", height=150)
        self.alerts_textbox.pack(expand=True, fill="both", padx=5, pady=5)

        # Attack Details Tab (using Treeview for table-like structure)
        attack_tab = self.results_notebook.tab("Model Attack Details")
        attack_tab.grid_columnconfigure(0, weight=1)
        attack_tab.grid_rowconfigure(0, weight=1)

        style = ttk.Style()
        # style.theme_use("default") # Use default for base ttk widgets
        # Configure Treeview colors (may depend on theme/OS)
        # style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0)
        # style.map('Treeview', background=[('selected', '#003d6b')], foreground=[('selected', 'white')])
        # style.configure("Treeview.Heading", background="#565b5e", foreground="white", relief="flat")
        # style.map("Treeview.Heading", background=[('active', '#6c7174')])

        self.attack_tree = ttk.Treeview(
            attack_tab,
            columns=("Time", "SrcIP", "SrcPort", "DstIP", "DstPort", "Proto", "Service", "Flag", "Bytes"),
            show="headings",
            height=7 # Initial height
            # style="Treeview" # Apply custom style if defined
        )
        self.attack_tree.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        # Define headings
        self.attack_tree.heading("Time", text="Time")
        self.attack_tree.heading("SrcIP", text="Source IP")
        self.attack_tree.heading("SrcPort", text="Src Port")
        self.attack_tree.heading("DstIP", text="Dest IP")
        self.attack_tree.heading("DstPort", text="Dst Port")
        self.attack_tree.heading("Proto", text="Protocol")
        self.attack_tree.heading("Service", text="Service")
        self.attack_tree.heading("Flag", text="Flag")
        self.attack_tree.heading("Bytes", text="Src Bytes")

        # Define column widths
        self.attack_tree.column("Time", width=150, anchor='w')
        self.attack_tree.column("SrcIP", width=110, anchor='w')
        self.attack_tree.column("SrcPort", width=60, anchor='center')
        self.attack_tree.column("DstIP", width=110, anchor='w')
        self.attack_tree.column("DstPort", width=60, anchor='center')
        self.attack_tree.column("Proto", width=50, anchor='center')
        self.attack_tree.column("Service", width=80, anchor='w')
        self.attack_tree.column("Flag", width=40, anchor='center')
        self.attack_tree.column("Bytes", width=70, anchor='e')

        # Add scrollbar for Treeview
        tree_scrollbar = ttk.Scrollbar(attack_tab, orient="vertical", command=self.attack_tree.yview)
        tree_scrollbar.grid(row=0, column=1, sticky="ns")
        self.attack_tree.configure(yscrollcommand=tree_scrollbar.set)


        # Ensure the predictor loaded message is visible if error occurred
        if self.predictor is None:
            self.status_label.configure(text="Status: ERROR - Model loading failed. Check console.", text_color="red")


    def populate_interfaces(self):
        """ Fetches and displays available network interfaces. """
        self.status_label.configure(text="Status: Fetching interfaces...")
        interfaces = capture_thread.get_interfaces() # Call function from capture_thread module
        self.interfaces_map = {iface["display"]: iface["id"] for iface in interfaces if iface["id"] is not None}
        display_names = list(self.interfaces_map.keys())

        if display_names:
            self.if_combobox.configure(values=display_names)
            self.if_combobox.set(display_names[0]) # Select first interface by default
            self.status_label.configure(text="Status: Idle")
        else:
            self.if_combobox.configure(values=["No suitable interfaces found"])
            self.if_combobox.set("No suitable interfaces found")
            self.start_button.configure(state="disabled") # Disable start if no interface
            self.status_label.configure(text="Status: Error - No interfaces found", text_color="orange")


    def start_capture(self):
        """ Starts the packet capture thread. """
        selected_display_name = self.if_combobox.get()
        interface_id = self.interfaces_map.get(selected_display_name)

        if not interface_id:
            self.status_label.configure(text="Status: Error - Please select a valid interface.", text_color="orange")
            return

        if self.is_capturing:
            print("Capture already running.")
            return

        # Check for Admin privileges (basic check for Windows)
        if platform.system() == "Windows":
            import ctypes
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except AttributeError:
                is_admin = False # Assume not admin if check fails
            if not is_admin:
                 self.status_label.configure(text="Status: ERROR - Please run as Administrator!", text_color="red")
                 # Consider showing a popup message box
                 import tkinter.messagebox
                 tkinter.messagebox.showerror("Permission Error", "Live packet capture requires Administrator privileges. Please restart the application as Administrator.")
                 return


        self.is_capturing = True
        self.clear_results() # Clear previous results when starting new capture
        self.status_label.configure(text=f"Status: Starting capture on {selected_display_name}...", text_color="green")
        print(f"Starting capture on interface ID: {interface_id}")

        # --- Reset counters ---
        self.total_packets_processed = 0
        self.model_attacks_detected = 0
        self.packet_count_label.configure(text="Packets Processed: 0")
        self.attack_count_label.configure(text="Model Attacks: 0")

        # --- Start capture thread ---
        self.capture_thread = capture_thread.CaptureThread(self.packet_queue, interface_id)
        self.capture_thread.start()

        # --- Update UI ---
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.if_combobox.configure(state="disabled")
        self.clear_button.configure(state="disabled")

        # --- Start processing queue ---
        self.after(PROCESSING_INTERVAL_MS, self.process_packet_queue)

    def stop_capture(self):
        """ Stops the packet capture thread. """
        if not self.is_capturing or not self.capture_thread:
            print("Capture not running.")
            return

        print("Stopping capture...")
        self.status_label.configure(text="Status: Stopping capture...", text_color="orange")
        self.capture_thread.stop()
        # Wait a short time for the thread to stop (adjust timeout if needed)
        self.capture_thread.join(timeout=2.0)
        self.is_capturing = False
        self.capture_thread = None

        # Check if thread actually stopped
        # (Scapy sniff might block longer sometimes)
        # We'll rely on the CAPTURE_FINISHED/ERROR signals in the queue

        # Update UI after attempting stop
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.if_combobox.configure(state="normal")
        self.clear_button.configure(state="normal")
        self.status_label.configure(text="Status: Idle")
        print("Capture stop signaled.")

    def process_packet_queue(self):
        """ Periodically processes packets from the queue. """
        if not self.is_capturing and self.packet_queue.empty():
            # Stop processing if capture stopped and queue is empty
            return

        packets_to_process = []
        try:
            while not self.packet_queue.empty(): # Process available packets
                packet = self.packet_queue.get_nowait()
                if isinstance(packet, str): # Check for signals
                    if packet == "CAPTURE_FINISHED":
                        print("Capture thread signaled finish.")
                        # Don't call stop_capture here, it was already called.
                        # Just update status if needed and stop processing loop.
                        if self.is_capturing: # If GUI didn't trigger stop yet
                           self.stop_capture() # Ensure UI state is correct
                        return # Stop checking queue
                    elif packet == "CAPTURE_ERROR":
                         print("Capture thread signaled an error.")
                         self.status_label.configure(text="Status: ERROR during capture. Check console.", text_color="red")
                         if self.is_capturing:
                             self.stop_capture() # Ensure UI state is correct
                         return # Stop checking queue
                else:
                    packets_to_process.append(packet)
                if len(packets_to_process) >= 50: # Process in batches
                    break
        except queue.Empty:
            pass # No packets currently in queue

        if packets_to_process:
            # print(f"Processing batch of {len(packets_to_process)} packets...")
            features_list = []
            processed_in_batch = 0
            for pkt in packets_to_process:
                features = extract_features_from_packet(pkt)
                if features:
                    features_list.append(features)
                    processed_in_batch += 1

            self.total_packets_processed += processed_in_batch
            self.packet_count_label.configure(text=f"Packets Processed: {self.total_packets_processed}")

            if features_list:
                feature_df = pd.DataFrame(features_list)
                # Ensure columns are correct - IMPORTANT
                try:
                    # Add missing KDD columns if any before passing to functions
                    for col in KDD_COLUMNS:
                        if col not in feature_df.columns:
                            feature_df[col] = 0
                    feature_df = feature_df[KDD_COLUMNS + ['_packet_time', '_src_ip', '_dst_ip', '_src_port', '_dst_port']]

                    # 1. Rule-based detection
                    new_rule_alerts = check_anomalies(feature_df)
                    if new_rule_alerts:
                         self.update_alerts_display(new_rule_alerts)

                    # 2. Model prediction
                    if self.predictor:
                        model_predictions = self.predictor.predict_traffic(feature_df)
                        if model_predictions is not None and len(model_predictions) > 0:
                            attack_indices = np.where(model_predictions == 1)[0]
                            if len(attack_indices) > 0:
                                 num_attacks_in_batch = len(attack_indices)
                                 self.model_attacks_detected += num_attacks_in_batch
                                 self.attack_count_label.configure(text=f"Model Attacks: {self.model_attacks_detected}")
                                 # Get details for display
                                 attack_details_batch = feature_df.iloc[attack_indices]
                                 self.update_attack_details_display(attack_details_batch)
                except Exception as e:
                    print(f"Error processing feature batch: {e}")


        # Schedule the next check only if still capturing
        if self.is_capturing:
            self.after(PROCESSING_INTERVAL_MS, self.process_packet_queue)


    def update_alerts_display(self, new_alerts):
        """ Appends new rule-based alerts to the textbox. """
        self.alerts_textbox.configure(state="normal")
        for alert in new_alerts:
            self.rule_alerts.append(alert) # Add to deque (automatically handles limit)
        # Rebuild text from deque
        display_text = "\n".join(self.rule_alerts)
        self.alerts_textbox.delete("1.0", "end")
        self.alerts_textbox.insert("1.0", display_text)
        self.alerts_textbox.see("end") # Scroll to bottom
        self.alerts_textbox.configure(state="disabled")


    def update_attack_details_display(self, attack_details_df):
        """ Adds new model-detected attacks to the Treeview. """
        if attack_details_df is None or attack_details_df.empty:
            return

        for index, row in attack_details_df.iterrows():
            # Format timestamp
            try:
                ts = pd.to_datetime(row.get('_packet_time', time.time()), unit='s').strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            except:
                ts = "Invalid Time"

            details = (
                ts,
                row.get('_src_ip', 'N/A'), row.get('_src_port', 'N/A'),
                row.get('_dst_ip', 'N/A'), row.get('_dst_port', 'N/A'),
                row.get('protocol_type', 'N/A'), row.get('service', 'N/A'),
                row.get('flag', 'N/A'), row.get('src_bytes', 'N/A')
            )
            # Insert at the beginning to show newest first
            self.attack_tree.insert("", 0, values=details)
            self.attack_details.appendleft(details) # Add to deque

            # Limit items displayed in Treeview (optional, could get slow)
            current_items = self.attack_tree.get_children('')
            if len(current_items) > MAX_DISPLAY_ITEMS:
                 self.attack_tree.delete(current_items[-1]) # Delete oldest (last item)


    def clear_results(self):
        """ Clears displayed results and resets counters/state. """
        # Clear GUI elements
        self.alerts_textbox.configure(state="normal")
        self.alerts_textbox.delete("1.0", "end")
        self.alerts_textbox.configure(state="disabled")
        for item in self.attack_tree.get_children():
            self.attack_tree.delete(item)

        # Clear internal state
        self.rule_alerts.clear()
        self.attack_details.clear()
        self.total_packets_processed = 0
        self.model_attacks_detected = 0
        clear_all_rule_state() # Clear state in anomaly detector module

        # Update counters
        self.packet_count_label.configure(text="Packets Processed: 0")
        self.attack_count_label.configure(text="Model Attacks: 0")
        print("Cleared results and anomaly state.")


    def on_closing(self):
        """ Handles window close event. """
        print("Close button pressed.")
        if self.is_capturing:
            print("Stopping capture before closing...")
            self.stop_capture() # Attempt graceful stop
            # Wait a bit longer here if needed
            time.sleep(0.5)
        print("Destroying window.")
        self.destroy()


if __name__ == "__main__":
    # --- Important check for Windows ---
    if platform.system() == "Windows":
        print("INFO: Live capture on Windows requires Npcap to be installed.")
        print("INFO: Application may need to be run as Administrator.")
        # Add check for admin rights if desired, or rely on Scapy error
    elif platform.system() == "Linux":
         print("INFO: Live capture on Linux typically requires root privileges.")
    elif platform.system() == "Darwin": # macOS
         print("INFO: Live capture on macOS typically requires root privileges.")

    app = App()
    app.mainloop()

```

**`README.md` (Updated)**

```markdown
# Live Network Traffic Analyzer

This tool captures network traffic live from a selected interface and analyzes it in near real-time using rule-based anomaly detection and a pre-trained Deep Neural Network (DNN) + Apriori model (based on the NSL-KDD dataset approach). It displays results in a desktop GUI.

**WARNING:**
*   **Administrator Privileges Required:** Live packet capture requires elevated (Administrator/root) privileges. Run the script accordingly.
*   **Feature Extraction Approximation:** The accuracy of the DNN model on live traffic might be significantly different from its reported accuracy on the NSL-KDD test set. Mapping raw packets to NSL-KDD features is an approximation.
*   **Performance:** Processing high-volume traffic in real-time with Python/Scapy can be CPU-intensive and might drop packets on busy networks.

## Features

*   Selects a network interface for live capture.
*   Captures packets in a separate thread to keep the GUI responsive.
*   Applies rule-based detection for potential SYN Floods and Port Scans.
*   Uses a pre-trained DNN model (approximating NSL-KDD features) for malicious traffic classification.
*   Applies a pre-calculated Apriori rule to filter potential DNN false positives.
*   Displays status, packet counts, rule-based alerts, and model-detected attacks in a CustomTkinter GUI.

## Folder Structure

```
live_network_analyzer/
├── main_gui.py             # Main CustomTkinter application file
├── requirements.txt        # Updated Python dependencies
├── analyzer/               # Core analysis logic module
│   ├── __init__.py
│   ├── packet_parser.py    # Extracts features from packets
│   ├── predictor.py        # Loads models and runs prediction
│   ├── anomaly_detector.py # Rule-based anomaly detection
│   └── utils.py            # Helper functions
├── capture_thread.py       # Handles live packet capture thread
├── models/                 # <<< PLACE YOUR TRAINED MODELS HERE >>>
│   ├── dnn_model.h5
│   ├── dnn_preprocessor.joblib
│   └── apriori_rule.pkl
└── README.md               # This file
```

## Setup

1.  **Clone or Download:** Get the project files.
2.  **Place Models:** Copy your trained model files (`dnn_model.h5`), preprocessor (`dnn_preprocessor.joblib`), and Apriori rule (`apriori_rule.pkl`) into the `models/` directory.
3.  **Install Packet Capture Library:**
    *   **Windows:** Install **[Npcap](https://npcap.com/)**. Download the latest installer and run it. Make sure to check the "Install Npcap in WinPcap API-compatible Mode" if you need compatibility with older tools, but Scapy generally works well with the native Npcap mode.
    *   **Linux:** Install `libpcap-dev` (Debian/Ubuntu: `sudo apt-get update && sudo apt-get install libpcap-dev`) or `libpcap-devel` (Fedora/CentOS: `sudo dnf install libpcap-devel`).
    *   **macOS:** Should be included with Xcode Command Line Tools, or install via Homebrew: `brew install libpcap`.
4.  **Install Python Dependencies:**
    *   Use a virtual environment (recommended):
        ```bash
        python -m venv venv
        # On Windows:
        venv\Scripts\activate
        # On Linux/macOS:
        source venv/bin/activate
        ```
    *   Install packages:
        ```bash
        pip install -r requirements.txt
        ```

## Running the Application

1.  **Activate Virtual Environment** (if used).
2.  **Run as Administrator/root:**
    *   **Windows:** Right-click your terminal (Command Prompt, PowerShell, etc.) or IDE and select "Run as administrator". Navigate to the project directory and run the script.
    *   **Linux/macOS:** Use `sudo`:
        ```bash
        sudo /path/to/your/venv/bin/python main_gui.py
        # Or if venv is active:
        # sudo python main_gui.py
        ```
3.  **Execute the script:**
    ```bash
    python main_gui.py
    ```

## Usage

1.  The application window will appear.
2.  Select the network interface you want to monitor from the dropdown menu.
3.  Click "Start Capture". The status should update, and packet/attack counters will increment as data is processed.
4.  View rule-based alerts in the "Rule Alerts" tab.
5.  View details of packets classified as attacks by the model in the "Model Attack Details" tab.
6.  Click "Stop Capture" to halt the monitoring process.
7.  Click "Clear Results" to reset the displays and internal anomaly detection state.

## Limitations & Considerations

*   **Requires Admin/root privileges.**
*   **Feature Mapping Inaccuracy:** The core limitation mentioned before still applies.
*   **Performance:** May struggle on networks with very high packet rates. Packet drops are possible.
*   **Memory Usage:** Storing raw packets in the queue (even temporarily) can consume memory. Processing batches helps mitigate this.
*   **GUI Responsiveness:** If processing takes too long, the GUI might still lag slightly between updates. Adjust `PROCESSING_INTERVAL_MS` or the batch size in `main_gui.py` if needed.
*   **Error Handling:** Basic error handling is included, but complex network or model issues might require more specific debugging. Check the console output for errors.
```

---

### Key Changes and How to Run

1.  **Install Dependencies:** Make sure you have `customtkinter` and `scapy` installed (`pip install -r requirements.txt`). Also, crucially, install **Npcap** on Windows.
2.  **Place Models:** Put your `dnn_model.h5`, `dnn_preprocessor.joblib`, and `apriori_rule.pkl` in the `models` folder.
3.  **Run as Administrator:** This is essential for live capture. Right-click your terminal/IDE and choose "Run as administrator".
4.  **Execute:** Run `python main_gui.py` from the administrator terminal within the project directory (and virtual environment if used).
5.  **Interact:** Use the GUI to select an interface and start/stop capture.

This version provides a functional desktop application for live analysis, addressing your core request while acknowledging the inherent challenges.