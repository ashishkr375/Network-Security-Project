# live_network_analyzer/capture_thread.py
import threading
import queue
import platform
import time
import traceback # Import traceback for detailed error logging

# Attempt to import Scapy components
try:
    from scapy.all import conf as scapy_conf
    from scapy.sendrecv import sniff
    # Conditionally import windows-specific function
    if platform.system() == "Windows":
        from scapy.arch.windows import get_windows_if_list
    else:
        # Define a dummy function for non-Windows platforms
        def get_windows_if_list(): print("Warning: get_windows_if_list called on non-Windows."); return []
    SCAPY_AVAILABLE = True
except ImportError as e:
    SCAPY_AVAILABLE = False
    print(f"ERROR: Failed to import Scapy components ({e}). Live capture disabled.")
    print("Please ensure Scapy is installed correctly: pip install --upgrade scapy")
    # Define dummies if necessary for the rest of the script to load
    if 'scapy_conf' not in locals(): 
        class DummyConf: pass; 
        scapy_conf = DummyConf()
    if 'sniff' not in locals(): 
        def sniff(*args, **kwargs): 
            print("Scapy 'sniff' unavailable.")
    if 'get_windows_if_list' not in locals(): 
        def get_windows_if_list(): 
            return []


class CaptureThread(threading.Thread):
    """
    Manages live packet capture in a separate thread to avoid blocking the GUI.
    Communicates with the main thread via a queue using specific signals.
    """
    def __init__(self, packet_queue, interface_id=None, packet_count=0, stop_timeout=1):
        """
        Initializes the capture thread.
        :param packet_queue: A queue.Queue to put captured packets (or signals) into.
        :param interface_id: The ID (name/GUID) of the interface to sniff on.
        :param packet_count: Number of packets to capture (0 for indefinite). (NOTE: GUI now uses timed capture)
        :param stop_timeout: How often sniff() checks the stop event (seconds).
        """
        super().__init__(daemon=True) # Make thread a daemon
        self.packet_queue = packet_queue
        self.interface_id = interface_id
        self.packet_count = packet_count # Kept for potential future use, but GUI enforces time
        self.stop_timeout = max(0.5, stop_timeout) # Ensure reasonable timeout
        self.stop_event = threading.Event() # Synchronization primitive
        self.sniffer = None # Holds the sniffer process/instance if needed
        self.capture_start_time = time.time()  # Initialize at creation
        self.last_packet_time = time.time()    # Initialize at creation
        self.packets_captured = 0
        self.capture_ready = threading.Event()  # Add synchronization event

    def _packet_callback(self, packet):
        """ Called by Scapy for each captured packet. Puts packet in queue. """
        if packet:
            try:
                self.packets_captured += 1
                self.last_packet_time = time.time()
                self.packet_queue.put(packet, block=False) # Non-blocking put
            except queue.Full:
                pass # Silently drop if queue is full to avoid blocking capture

    def run(self):
        """ The main logic of the capture thread, starts the sniffing process. """
        if not SCAPY_AVAILABLE:
            print("ERROR: Scapy not available in CaptureThread.run()")
            self.packet_queue.put("CAPTURE_ERROR: Scapy unavailable")
            return

        print(f"Capture thread starting on interface ID: '{self.interface_id}'")
        self.stop_event.clear() # Ensure stop flag is reset
        self.capture_start_time = time.time()  # Reset at actual start
        self.last_packet_time = time.time()    # Reset at actual start
        self.capture_ready.set()  # Signal that capture is ready

        if self.interface_id is None:
             print(f"ERROR: No interface ID provided to CaptureThread.")
             self.packet_queue.put("CAPTURE_ERROR: No interface ID")
             return

        try:
            print(f"Starting sniff on '{self.interface_id}' with promisc=True")
            
            while not self.stop_event.is_set():
                try:
                    # Start a new sniff session with a short timeout
                    sniff(
                        iface=self.interface_id,
                        prn=self._packet_callback,
                        store=False,
                        timeout=0.5,  # Short timeout to check stop_event frequently
                        promisc=True,
                        filter="tcp or icmp"  # This basic filter captures all TCP (including SYN) and ICMP
                    )
                    
                    # Check if we should continue capturing
                    current_time = time.time()
                    if current_time - self.last_packet_time > 5 and self.packets_captured > 0:
                        print("No packets received for 5 seconds, checking interface...")
                        self.last_packet_time = current_time
                    
                    # Small sleep to prevent tight loop
                    time.sleep(0.1)
                    
                except Exception as sniff_error:
                    print(f"Error during sniff iteration: {sniff_error}")
                    if "permission" in str(sniff_error).lower():
                        raise  # Re-raise permission errors
                    time.sleep(0.5)  # Wait before retry on other errors
            
            print(f"Capture loop ended. Total packets captured: {self.packets_captured}")

        except OSError as e:
            error_msg = str(e).lower()
            if "permission" in error_msg:
                print("ERROR: Permission denied. Please run as Administrator.")
                self.packet_queue.put("CAPTURE_ERROR: Permission denied - Run as Administrator")
            elif "adapter" in error_msg or "device" in error_msg:
                print(f"ERROR: Interface '{self.interface_id}' not found or inaccessible")
                self.packet_queue.put(f"CAPTURE_ERROR: Interface not found - {self.interface_id}")
            else:
                print(f"ERROR: OSError during capture: {e}")
                self.packet_queue.put(f"CAPTURE_ERROR: {str(e)}")
            
        except Exception as e:
            print(f"ERROR: Unexpected error during capture: {e}")
            traceback.print_exc()
            self.packet_queue.put(f"CAPTURE_ERROR: {str(e)}")
            
        finally:
            capture_duration = time.time() - self.capture_start_time
            print(f"Capture ended after {capture_duration:.1f} seconds. Packets: {self.packets_captured}")
            if self.stop_event.is_set():
                print("Capture stopped by request")
            self.packet_queue.put("CAPTURE_THREAD_EXITED")

    def stop(self):
        """ Signals the capture thread to stop sniffing. """
        if not self.stop_event.is_set(): # Avoid printing multiple times
            print(f"Signaling capture thread to stop on interface '{self.interface_id}'...")
            self.stop_event.set() # Set the event flag, sniff() will check this via stop_filter

# --- get_interfaces Function ---
def get_interfaces():
    """
    Gets a list of network interfaces suitable for display in the GUI.
    Returns a list of dictionaries: [{'display': 'User Friendly Name', 'id': 'Scapy ID'}, ...]
    Includes more robust error checking.
    """
    interfaces = []
    print("Fetching network interfaces...")

    if not SCAPY_AVAILABLE:
         print("Scapy is not available. Cannot fetch interfaces.")
         interfaces.append({"display": "Scapy unavailable", "id": None})
         return interfaces

    try:
        if platform.system() == "Windows":
            # Ensure get_windows_if_list was defined and usable
            if 'get_windows_if_list' not in globals() or not callable(get_windows_if_list):
                 print("ERROR: Scapy's get_windows_if_list function is missing or not callable.")
                 raise RuntimeError("Windows interface function missing")

            raw_ifs = get_windows_if_list()
            print(f"Raw interfaces from get_windows_if_list: {raw_ifs}") # Debug print

            if raw_ifs is None:
                 print("Warning: get_windows_if_list() returned None. Npcap issue?")
                 raw_ifs = []
            elif not isinstance(raw_ifs, list):
                print(f"Warning: get_windows_if_list() did not return a list (got {type(raw_ifs)}).")
                raw_ifs = []

            for iface_dict in raw_ifs:
                 if isinstance(iface_dict, dict):
                     # Prefer description for display, fallback to name
                     display_name = iface_dict.get('description') or iface_dict.get('name') or 'Unknown Interface'
                     # Use 'guid' if present and looks like a GUID, otherwise 'name' for Scapy ID
                     # Scapy often prefers the 'name' like 'Ethernet', 'Wi-Fi'
                     sniff_id = iface_dict.get('name') # Primarily use name for Scapy ID on Windows
                     guid = iface_dict.get('guid')

                     # Add GUID to display name for clarity if available
                     display_name_full = display_name
                     if guid: display_name_full += f" ({guid})"

                     if display_name and sniff_id:
                         print(f"  Found Interface: Display='{display_name_full}', ID='{sniff_id}'")
                         interfaces.append({"display": display_name_full, "id": sniff_id})
                     else:
                          print(f"  Skipped Interface (missing name/id): {iface_dict}")
                 else:
                     print(f"Warning: Unexpected item format in get_windows_if_list result: {iface_dict}")

        else: # Assume Linux/macOS
             # Check scapy_conf structure before accessing
             if hasattr(scapy_conf, 'ifaces') and hasattr(scapy_conf.ifaces, 'data'):
                 raw_ifs = scapy_conf.ifaces.data
                 print(f"Raw interfaces from scapy_conf.ifaces.data: {raw_ifs}") # Debug print
                 if not raw_ifs: print("Warning: scapy_conf.ifaces.data is empty.")
                 for name, iface_obj in raw_ifs.items():
                      # Ensure name is a string (keys should be)
                      if not isinstance(name, str):
                          print(f"Warning: Skipping non-string interface name {name}")
                          continue
                      # Create a descriptive name using IP and MAC if available
                      ip = getattr(iface_obj, 'ip', 'No IP')
                      mac = getattr(iface_obj, 'mac', '')
                      display_name = f"{name} ({ip})" + (f" [{mac}]" if mac else "")
                      sniff_id = name # On Linux/macOS, the name is the ID
                      print(f"  Found Interface: Display='{display_name}', ID='{sniff_id}'")
                      interfaces.append({"display": display_name, "id": sniff_id})
             else:
                  print("Warning: scapy_conf object missing 'ifaces.data'. Cannot list interfaces.")
                  raise RuntimeError("Scapy conf structure missing")

    except Exception as e:
        print(f"ERROR during interface enumeration: {e}")
        traceback.print_exc()
        interfaces.clear() # Clear partial results on error
        interfaces.append({"display": "Error fetching interfaces", "id": None})

    # Final check and fallback
    print(f"Processed interfaces before final check: {interfaces}")
    if not interfaces or all(iface.get("id") is None for iface in interfaces):
         print("No usable interfaces found after processing. Adding fallback.")
         interfaces = [{"display": "No suitable interfaces found", "id": None}]

    print(f"Final interfaces returned: {[iface['display'] for iface in interfaces]}")
    return interfaces