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