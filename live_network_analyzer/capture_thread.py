# capture_thread.py
import threading
import queue
import platform
import time

# Attempt to import Scapy components from their specific modules
try:
    from scapy.all import conf as scapy_conf           # Config object
    # *** REMOVED Lfilter from this import ***
    from scapy.sendrecv import sniff                   # Core sniffing function
    from scapy.arch.windows import get_windows_if_list # Windows specific function
    SCAPY_AVAILABLE = True
except ImportError as e:
    # Provide helpful error messages if imports fail
    SCAPY_AVAILABLE = False # Assume not available initially
    if 'get_windows_if_list' in str(e):
        print("ERROR: Could not import 'get_windows_if_list'. Is Scapy installed correctly for Windows?")
        # Define dummy only if needed and platform matches
        if platform.system() == "Windows":
            def get_windows_if_list(): print("Warning: Scapy's get_windows_if_list unavailable, returning empty."); return []
    elif 'sniff' in str(e):
         print("ERROR: Could not import 'sniff' from 'scapy.sendrecv'. Critical Scapy function missing.")
         # SCAPY_AVAILABLE remains False
    else:
        # General Scapy import failure
        print(f"ERROR: Scapy failed to import ({e}). Live capture is disabled.")
        print("Please install/reinstall Scapy: pip install --upgrade scapy")
        # SCAPY_AVAILABLE remains False

    # Define dummy replacements if Scapy is not available or critical parts failed
    if not SCAPY_AVAILABLE:
        # Define get_windows_if_list dummy if it wasn't defined above and needed
        if platform.system() == "Windows" and 'get_windows_if_list' not in locals():
             def get_windows_if_list(): return []
        # Define sniff dummy if needed
        if 'sniff' not in locals():
             def sniff(*args, **kwargs): print("Scapy 'sniff' not available.")
        # Define conf dummy if needed
        if 'scapy_conf' not in locals():
             class DummyConf: pass; scapy_conf = DummyConf()


class CaptureThread(threading.Thread):
    """
    Manages live packet capture in a separate thread to avoid blocking the GUI.
    Communicates with the main thread via a queue.
    """
    def __init__(self, packet_queue, interface_id=None, packet_count=0, stop_timeout=1):
        """
        Initializes the capture thread.
        :param packet_queue: A queue.Queue to put captured packets (or signals) into.
        :param interface_id: The ID (name/GUID) of the interface to sniff on.
        :param packet_count: Number of packets to capture (0 for indefinite).
        :param stop_timeout: How often sniff() checks the stop event (seconds).
        """
        super().__init__(daemon=True) # Make thread a daemon
        self.packet_queue = packet_queue
        self.interface_id = interface_id
        self.packet_count = packet_count
        # Ensure stop_timeout is reasonable (e.g., not zero)
        self.stop_timeout = max(0.5, stop_timeout) # Use at least 0.5 sec timeout
        self.stop_event = threading.Event() # Synchronization primitive
        self.sniffer = None # Holds the sniffer process/instance if needed

    def _packet_callback(self, packet):
        """ Called by Scapy for each captured packet. Puts packet in queue. """
        if packet:
            try:
                self.packet_queue.put(packet, block=False) # Non-blocking put
            except queue.Full:
                pass # print("Warning: Packet queue is full. Dropping packet.")

    def run(self):
        """ The main logic of the capture thread, starts the sniffing process. """
        if not SCAPY_AVAILABLE:
            self.packet_queue.put("CAPTURE_ERROR: Scapy not available")
            return

        print(f"Capture thread starting on interface ID: '{self.interface_id}'")
        self.stop_event.clear() # Ensure stop flag is reset

        if self.interface_id is None and platform.system() != "Windows":
            print("Warning: No interface specified for capture on non-Windows OS. Scapy might choose a default.")

        sniff_exception = None
        try:
            print(f"Calling sniff(iface='{self.interface_id}', count={self.packet_count}, promisc=True, timeout={self.stop_timeout}, ...)") # Debug print
            # Call sniff (imported from scapy.sendrecv)
            sniff(
                iface=self.interface_id,
                prn=self._packet_callback,
                count=self.packet_count,
                store=False,
                stop_filter=lambda p: self.stop_event.is_set(),
                timeout=self.stop_timeout, # Check stop_event periodically
                promisc=True # Explicitly enable promiscuous mode
                # lfilter is no longer imported or used
            )
            # If sniff finishes without exception:
            print("sniff() function completed.") # Debug print
            # Only signal count finish if count > 0 and it wasn't stopped manually
            if not self.stop_event.is_set() and self.packet_count != 0:
                 print("Capture thread finished: Packet count reached.")
                 self.packet_queue.put("CAPTURE_FINISHED_COUNT")

        except OSError as e:
             sniff_exception = e
             print(f"ERROR during sniff() on '{self.interface_id}': {e}")
             print("-> Check Permissions (Admin/root), Npcap/libpcap installation, and Interface ID validity.")
             self.packet_queue.put("CAPTURE_ERROR: OSError")
        except Exception as e:
            sniff_exception = e
            print(f"An unexpected error occurred during sniff(): {e}")
            self.packet_queue.put("CAPTURE_ERROR: Unexpected")
        finally:
            # This block always executes
            if self.stop_event.is_set():
                 print(f"Capture thread received stop signal for interface: {self.interface_id}")
            # Check if sniff exited without error, without stop signal, when infinite capture was intended
            elif sniff_exception is None and self.packet_count == 0 and not self.stop_event.is_set():
                 print(f"Capture thread sniff() exited unexpectedly without error or stop signal (Interface: {self.interface_id}).")
                 self.packet_queue.put("CAPTURE_ERROR: Sniff ended unexpectedly")

            # Always signal that the thread itself is exiting its run method
            self.packet_queue.put("CAPTURE_THREAD_EXITED")
            print(f"Capture thread run method exiting for interface: {self.interface_id}")


    def stop(self):
        """ Signals the capture thread to stop sniffing. """
        if not self.stop_event.is_set(): # Avoid printing multiple times if already stopping
            print("Signaling capture thread to stop...")
            self.stop_event.set() # Set the event flag, sniff() will check this via stop_filter

def get_interfaces():
    """
    Gets a list of network interfaces suitable for display in the GUI.
    Returns a list of dictionaries: [{'display': 'User Friendly Name', 'id': 'Scapy ID'}, ...]
    """
    interfaces = []
    print("Fetching network interfaces...")
    # Check again if Scapy is usable *before* trying to use its functions
    if not SCAPY_AVAILABLE:
         print("Scapy not available, cannot fetch interfaces.")
         interfaces.append({"display": "Scapy not installed/usable", "id": None})
         return interfaces

    try:
        if platform.system() == "Windows":
            # Ensure get_windows_if_list was defined (even as dummy)
            if 'get_windows_if_list' not in globals():
                 print("ERROR: get_windows_if_list function is not defined.")
                 raise RuntimeError("Interface function missing")

            raw_ifs = get_windows_if_list() # Use the potentially dummy or real function
            if raw_ifs is None: # Add check for None return
                 print("Warning: get_windows_if_list() returned None.")
                 raw_ifs = []
            elif not raw_ifs:
                 print("Warning: get_windows_if_list() returned empty list.")

            for iface_dict in raw_ifs:
                 # Check if it's a dictionary-like object before accessing keys
                 if hasattr(iface_dict, 'get'):
                     display_name = iface_dict.get('description', iface_dict.get('name', 'Unknown Interface'))
                     sniff_id = iface_dict.get('name')
                     if display_name and sniff_id:
                         interfaces.append({"display": f"{display_name}", "id": sniff_id})
                 else:
                     print(f"Warning: Unexpected item format in get_windows_if_list result: {iface_dict}")

        else: # Assume Linux/macOS
             # Use scapy_conf if available, otherwise handle potential attribute error
             if hasattr(scapy_conf, 'ifaces') and hasattr(scapy_conf.ifaces, 'data'):
                 raw_ifs = scapy_conf.ifaces.data
                 if not raw_ifs: print("Warning: scapy_conf.ifaces.data is empty.")
                 for name, iface_obj in raw_ifs.items():
                      # Create a descriptive name using IP and MAC if available
                      ip = getattr(iface_obj, 'ip', 'No IP')
                      mac = getattr(iface_obj, 'mac', '')
                      display_name = f"{name} ({ip})" + (f" [{mac}]" if mac else "")
                      interfaces.append({"display": display_name, "id": name}) # 'name' is the ID for sniff
             else:
                  print("Warning: scapy_conf object doesn't have 'ifaces' or 'ifaces.data' attribute.")

    except Exception as e:
        # Catch potential errors during interface enumeration
        print(f"ERROR during interface enumeration: {e}")
        # Add specific error details if possible
        import traceback
        traceback.print_exc()
        interfaces.append({"display": "Error fetching interfaces", "id": None})

    # --- Crucial: Ensure the final log message is printed ---
    print(f"Found interfaces for GUI: {[iface['display'] for iface in interfaces]}") # This line MUST be reached

    # Provide a fallback if, after all attempts, no valid interfaces were added
    if not interfaces or all(iface.get("id") is None for iface in interfaces):
         print("No usable interfaces found after processing.")
         # Clear list and add the "No suitable" message
         interfaces = [{"display": "No suitable interfaces found", "id": None}]

    return interfaces