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
    """
    Converts Scapy TCP flags to NSL-KDD flag strings.
    Improved to better detect SYN packets from different types of network captures.
    """
    try:
        # If flags is an object with flag attributes (like Scapy's TCP flags)
        if hasattr(flags, 'S') and hasattr(flags, 'A'):
            if flags.R: return 'REJ'  # Reset flag
            elif flags.S and not flags.A: return 'S0'  # SYN without ACK (connection attempt)
            elif flags.F: return 'SH'  # FIN flag (simplified)
            elif flags.S and flags.A: return 'S1'  # SYN+ACK (connection response)
            elif flags.A and not flags.S and not flags.F and not flags.R: return 'SF'  # Normal established connection
            else: return 'OTH'  # Other flag combinations
        
        # If flags is an integer (raw flag value)
        elif isinstance(flags, int):
            S = bool(flags & 0x02)  # SYN flag is bit 1
            A = bool(flags & 0x10)  # ACK flag is bit 4
            R = bool(flags & 0x04)  # RST flag is bit 2
            F = bool(flags & 0x01)  # FIN flag is bit 0
            
            if R: return 'REJ'
            elif S and not A: return 'S0'
            elif F: return 'SH'
            elif S and A: return 'S1'
            elif A and not S and not F and not R: return 'SF'
            else: return 'OTH'
            
        # Handle string representation for flexibility
        elif isinstance(flags, str):
            flags = flags.upper()
            if 'R' in flags: return 'REJ'
            elif 'S' in flags and 'A' not in flags: return 'S0'
            elif 'F' in flags: return 'SH'
            elif 'S' in flags and 'A' in flags: return 'S1'
            elif 'A' in flags and 'S' not in flags and 'F' not in flags and 'R' not in flags: return 'SF'
            else: return 'OTH'
            
    except Exception as e:
        print(f"Error in flag conversion: {e}")
    
    # Default fallback
    return 'OTH'

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