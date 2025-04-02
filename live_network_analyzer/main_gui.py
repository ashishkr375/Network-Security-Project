# main_gui.py
import customtkinter as ctk
from tkinter import ttk, messagebox # Use standard tkinter messagebox
import queue
import threading
import time
import platform
import pandas as pd
import numpy as np # Import numpy for checking prediction results
from collections import deque
import os # To check for model directory

# Analyzer components
from analyzer.packet_parser import extract_features_from_packet, KDD_COLUMNS
from analyzer.predictor import TrafficPredictor
from analyzer.anomaly_detector import check_anomalies, clear_all_rule_state
# Capture thread and interface fetching
import capture_thread

# --- Configuration ---
APP_TITLE = "Live Network Traffic Analyzer"
THEME = "System" # Options: "System", "Dark", "Light"
COLOR_THEME = "blue" # Options: "blue", "green", "dark-blue"
MODEL_DIR = 'models'
MAX_PACKETS_IN_QUEUE = 2000 # Max packets to buffer before potential drops
PROCESSING_INTERVAL_MS = 300 # Check queue every ~300ms
GUI_UPDATE_BATCH_SIZE = 50   # Update GUI elements after processing this many packets
MAX_DISPLAY_ITEMS = 150 # Max items (alerts/attacks) shown in GUI lists

# --- UI Color Definitions ---
# Use tuples for light/dark mode if needed, or single values
ATTACK_ROW_BG_COLOR = ("#FFD2D2", "#6B0000") # Light red (light), Dark red (dark) - Adjust as needed
ATTACK_ROW_FG_COLOR = ("black", "white")    # Black text (light), White text (dark)
NORMAL_TEXT_COLOR = ("black", "white")      # Default text color (dark, light)
ATTACK_LABEL_COLOR = ("red", "coral")       # Color for attack counter text (dark, light)

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(APP_TITLE)
        self.geometry("1000x800") # Increased size slightly
        ctk.set_appearance_mode(THEME)
        ctk.set_default_color_theme(COLOR_THEME)

        # --- State Variables ---
        self.capture_thread_instance = None
        self.packet_queue = queue.Queue(maxsize=MAX_PACKETS_IN_QUEUE)
        self.is_capturing = False
        self.total_packets_processed = 0
        self.model_attacks_detected = 0
        self.packets_since_last_gui_update = 0
        self.rule_alerts_list = deque(maxlen=MAX_DISPLAY_ITEMS)
        self.attack_details_list = deque(maxlen=MAX_DISPLAY_ITEMS)

        # --- Load Predictor ---
        self.predictor = None
        if not os.path.exists(MODEL_DIR):
             print(f"ERROR: Models directory '{MODEL_DIR}' not found.")
             messagebox.showerror("Initialization Error", f"Models directory '{MODEL_DIR}' not found.\nPlease create it and place model files inside.")
        else:
            try:
                predictor_instance = TrafficPredictor(model_dir=MODEL_DIR)
                if predictor_instance.is_loaded: self.predictor = predictor_instance; print("Predictor initialized successfully.")
                else: messagebox.showerror("Initialization Error", "Predictor loaded but failed to initialize artifacts. Prediction disabled."); self.predictor = None
            except Exception as e: print(f"ERROR during TrafficPredictor initialization: {e}"); messagebox.showerror("Initialization Error", f"Failed to initialize predictor: {e}\nPrediction disabled."); self.predictor = None

        # --- UI Elements ---
        self.create_widgets()
        self.populate_interfaces()

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        """ Creates and arranges all the GUI elements. """
        self.grid_columnconfigure(0, weight=1) # Make main column expandable
        self.grid_rowconfigure(2, weight=1)    # Make results row expandable

        # --- Top Frame: Controls ---
        self.controls_frame = ctk.CTkFrame(self) # Added border for visual separation
        self.controls_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.controls_frame.grid_columnconfigure(1, weight=1) # Make combobox expand

        self.if_label = ctk.CTkLabel(self.controls_frame, text="Network Interface:")
        self.if_label.grid(row=0, column=0, padx=(10, 5), pady=10, sticky="w")
        self.if_combobox = ctk.CTkComboBox(self.controls_frame, state="readonly", values=["Fetching..."])
        self.if_combobox.grid(row=0, column=1, padx=5, pady=10, sticky="ew")
        self.start_button = ctk.CTkButton(self.controls_frame, text="Start Capture", command=self.start_capture, width=120)
        self.start_button.grid(row=0, column=2, padx=5, pady=10)
        self.stop_button = ctk.CTkButton(self.controls_frame, text="Stop Capture", command=self.stop_capture, state="disabled", width=120)
        self.stop_button.grid(row=0, column=3, padx=(5, 10), pady=10)

        # --- Middle Frame: Status & Counts ---
        self.status_frame = ctk.CTkFrame(self) # Added border
        self.status_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="ew")
        self.status_frame.grid_columnconfigure(3, weight=1) # Push clear button right

        self.status_label = ctk.CTkLabel(self.status_frame, text="Status: Idle", anchor="w", width=300) # Give status more width
        self.status_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.packet_count_label = ctk.CTkLabel(self.status_frame, text="Packets Processed: 0", anchor="w")
        self.packet_count_label.grid(row=0, column=1, padx=10, pady=5, sticky="w") # Reduced padding slightly
        self.attack_count_label = ctk.CTkLabel(self.status_frame, text="Model Attacks: 0", anchor="w", text_color=NORMAL_TEXT_COLOR)
        self.attack_count_label.grid(row=0, column=2, padx=10, pady=5, sticky="w") # Reduced padding slightly
        self.clear_button = ctk.CTkButton(self.status_frame, text="Clear Results", command=self.clear_results, width=110)
        self.clear_button.grid(row=0, column=3, padx=10, pady=5, sticky="e")

        # --- Bottom Frame: Results Tabs ---
        self.results_notebook = ctk.CTkTabview(self)
        self.results_notebook.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="nsew") # Expand
        self.results_notebook.add("Rule Alerts")
        self.results_notebook.add("Model Attack Details")
        self.results_notebook.set("Rule Alerts")

        # --- Rule Alerts Tab Content ---
        alerts_tab = self.results_notebook.tab("Rule Alerts")
        alerts_tab.grid_columnconfigure(0, weight=1); alerts_tab.grid_rowconfigure(0, weight=1)
        self.alerts_textbox = ctk.CTkTextbox(alerts_tab, state="disabled", wrap="word", activate_scrollbars=True)
        self.alerts_textbox.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        # --- Attack Details Tab Content (Treeview) ---
        attack_tab = self.results_notebook.tab("Model Attack Details")
        attack_tab.grid_columnconfigure(0, weight=1); attack_tab.grid_rowconfigure(0, weight=1)

        # Treeview Styling
        style = ttk.Style()
        current_mode = ctk.get_appearance_mode()
        mode_index = 1 if current_mode == "Dark" else 0 # 0=light, 1=dark

        tree_bg = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkTextbox"]["fg_color"])
        tree_fg = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkLabel"]["text_color"])
        heading_fg = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkButton"]["fg_color"])
        heading_text = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkButton"]["text_color"])
        selected_color = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkButton"]["hover_color"]) # Use hover for selection

        style.configure("Treeview", background=tree_bg, foreground=tree_fg, fieldbackground=tree_bg, borderwidth=1, rowheight=25)
        style.map('Treeview', background=[('selected', selected_color)], foreground=[('selected', heading_text)])
        style.configure("Treeview.Heading", background=heading_fg, foreground=heading_text, relief="flat", font=('Segoe UI', 10, 'bold'))
        style.map("Treeview.Heading", background=[('active', heading_fg)])


        tree_columns = ("Time", "SrcIP", "SrcPort", "DstIP", "DstPort", "Proto", "Service", "Flag", "Bytes")
        # *** Create the Treeview widget HERE ***
        self.attack_tree = ttk.Treeview(
            attack_tab,
            columns=tree_columns,
            show="headings",
            style="Treeview"
        )
        self.attack_tree.grid(row=0, column=0, padx=(5,0), pady=5, sticky="nsew") # Expand treeview

        # *** Configure Treeview Tag AFTER creating self.attack_tree ***
        attack_bg = ATTACK_ROW_BG_COLOR[mode_index]
        attack_fg = ATTACK_ROW_FG_COLOR[mode_index]
        self.attack_tree.tag_configure('attack_row', background=attack_bg, foreground=attack_fg)
        # --- End Tag Configuration ---


        # Define headings and columns
        for col in tree_columns: self.attack_tree.heading(col, text=col)
        self.attack_tree.column("Time", width=160, anchor='w', stretch=False)
        self.attack_tree.column("SrcIP", width=120, anchor='w', stretch=False)
        self.attack_tree.column("SrcPort", width=70, anchor='center', stretch=False)
        self.attack_tree.column("DstIP", width=120, anchor='w', stretch=False)
        self.attack_tree.column("DstPort", width=70, anchor='center', stretch=False)
        self.attack_tree.column("Proto", width=60, anchor='center', stretch=False)
        self.attack_tree.column("Service", width=90, anchor='w', stretch=False)
        self.attack_tree.column("Flag", width=50, anchor='center', stretch=False)
        self.attack_tree.column("Bytes", width=80, anchor='e', stretch=True)

        # Scrollbar (use CTkScrollbar)
        tree_scrollbar = ctk.CTkScrollbar(attack_tab, command=self.attack_tree.yview)
        tree_scrollbar.grid(row=0, column=1, padx=(0,5), pady=5, sticky="ns")
        self.attack_tree.configure(yscrollcommand=tree_scrollbar.set)

    # --- Keep the rest of the methods unchanged ---
    # populate_interfaces, start_capture, stop_capture, process_packet_queue,
    # update_alerts_display, update_attack_details_display, clear_results, on_closing
    # (Copy these methods exactly from the previous response where they were working)

    def populate_interfaces(self):
        """ Fetches and displays available network interfaces. """
        self.status_label.configure(text="Status: Fetching interfaces...")
        self.update_idletasks()
        try:
            interfaces = capture_thread.get_interfaces()
            self.interfaces_map = {iface["display"]: iface["id"] for iface in interfaces if iface.get("id") is not None}
            display_names = list(self.interfaces_map.keys())
            if display_names:
                self.if_combobox.configure(values=display_names)
                self.if_combobox.set(display_names[0])
                self.status_label.configure(text="Status: Idle", text_color=NORMAL_TEXT_COLOR)
                self.start_button.configure(state="normal")
            else:
                self.if_combobox.configure(values=["No suitable interfaces found"])
                self.if_combobox.set("No suitable interfaces found")
                self.start_button.configure(state="disabled")
                self.status_label.configure(text="Status: Error - No interfaces found", text_color="orange")
        except Exception as e:
            print(f"Error during interface population: {e}")
            self.status_label.configure(text="Status: Error fetching interfaces", text_color="red")
            self.if_combobox.configure(values=["Error fetching interfaces"])
            self.if_combobox.set("Error fetching interfaces")
            self.start_button.configure(state="disabled")


    def start_capture(self):
        """ Validates selection and starts the packet capture thread. """
        selected_display_name = self.if_combobox.get()
        interface_id = self.interfaces_map.get(selected_display_name)
        if not interface_id: messagebox.showerror("Interface Error", "Please select a valid network interface."); return
        if self.is_capturing: print("Capture already running."); return

        if platform.system() == "Windows":
            import ctypes
            try: is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except AttributeError: is_admin = False
            if not is_admin: messagebox.showerror("Permission Error", "Requires Administrator privileges."); return

        self.is_capturing = True
        self.clear_results()
        status_text = f"Status: Capturing on {selected_display_name}..."
        self.status_label.configure(text=status_text, text_color=NORMAL_TEXT_COLOR)
        print(f"Attempting to start capture on interface ID: {interface_id}")
        self.total_packets_processed = 0; self.model_attacks_detected = 0; self.packets_since_last_gui_update = 0
        self.packet_count_label.configure(text="Packets Processed: 0")
        self.attack_count_label.configure(text="Model Attacks: 0", text_color=NORMAL_TEXT_COLOR)

        self.capture_thread_instance = capture_thread.CaptureThread(self.packet_queue, interface_id)
        self.capture_thread_instance.start()
        self.start_button.configure(state="disabled"); self.stop_button.configure(state="normal")
        self.if_combobox.configure(state="disabled"); self.clear_button.configure(state="disabled")
        self.after(PROCESSING_INTERVAL_MS, self.process_packet_queue)


    def stop_capture(self):
        """ Signals the capture thread to stop and updates the GUI. """
        if not self.is_capturing or not self.capture_thread_instance: print("Capture not running."); return
        print("Stopping packet capture..."); self.status_label.configure(text="Status: Stopping capture...", text_color="orange")
        self.capture_thread_instance.stop()
        self.is_capturing = False; self.capture_thread_instance = None
        self.start_button.configure(state="normal"); self.stop_button.configure(state="disabled")
        self.if_combobox.configure(state="normal"); self.clear_button.configure(state="normal")
        self.status_label.configure(text="Status: Idle", text_color=NORMAL_TEXT_COLOR)
        print("Capture stop signaled. Processing remaining queue...")


    def process_packet_queue(self):
        """ Periodically checks the queue and processes packets in batches. """
        if not self.is_capturing and self.packet_queue.empty(): return

        packets_in_batch = []; batch_start_time = time.time(); processed_count_this_cycle = 0
        max_proc_time = 0.2 # Max seconds per cycle
        try:
            while time.time() - batch_start_time < max_proc_time:
                packet = self.packet_queue.get_nowait()
                processed_count_this_cycle += 1
                if isinstance(packet, str): # Handle signals
                    if packet.startswith("CAPTURE_ERROR"):
                        error_detail = packet.split(":", 1)[-1].strip()
                        print(f"Capture thread error: {error_detail}")
                        self.status_label.configure(text=f"Status: ERROR - {error_detail}.", text_color="red")
                        if self.is_capturing: self.stop_capture(); return
                    elif packet == "CAPTURE_FINISHED_COUNT":
                        print("Capture thread finished (count).")
                        if self.is_capturing: self.stop_capture(); return
                    elif packet == "CAPTURE_THREAD_EXITED":
                        print("Capture thread exited.")
                        if self.is_capturing: self.stop_capture(); return
                    else: print(f"Unknown signal: {packet}")
                else: packets_in_batch.append(packet)
                if len(packets_in_batch) >= GUI_UPDATE_BATCH_SIZE * 2: break
        except queue.Empty: pass

        if packets_in_batch:
            features_list = [extract_features_from_packet(pkt) for pkt in packets_in_batch]
            features_list = [f for f in features_list if f is not None]
            batch_processed_count = len(features_list)
            self.total_packets_processed += batch_processed_count
            if features_list:
                feature_df = pd.DataFrame(features_list)
                metadata_cols = ['_packet_time', '_src_ip', '_dst_ip', '_src_port', '_dst_port']
                present_metadata = [col for col in metadata_cols if col in feature_df.columns]
                all_cols = KDD_COLUMNS + present_metadata
                try:
                    for col in KDD_COLUMNS:
                        if col not in feature_df.columns: feature_df[col] = 0
                    feature_df = feature_df[all_cols]
                    new_rule_alerts = check_anomalies(feature_df)
                    if new_rule_alerts: self.update_alerts_display(new_rule_alerts)
                    if self.predictor:
                        model_predictions = self.predictor.predict_traffic(feature_df) # Uses adjusted threshold
                        if model_predictions is not None and len(model_predictions) > 0:
                            attack_indices = np.where(model_predictions == 1)[0]
                            if len(attack_indices) > 0:
                                self.model_attacks_detected += len(attack_indices)
                                attack_details_batch_df = feature_df.iloc[attack_indices]
                                self.update_attack_details_display(attack_details_batch_df)
                        elif model_predictions is None: print("Model prediction returned None.")
                except Exception as e: print(f"Error during batch processing: {e}")

            self.packets_since_last_gui_update += batch_processed_count
            if self.packets_since_last_gui_update >= GUI_UPDATE_BATCH_SIZE:
                self.packet_count_label.configure(text=f"Packets Processed: {self.total_packets_processed}")
                attack_color = ATTACK_LABEL_COLOR if self.model_attacks_detected > 0 else NORMAL_TEXT_COLOR
                self.attack_count_label.configure(text=f"Model Attacks: {self.model_attacks_detected}", text_color=attack_color)
                self.packets_since_last_gui_update = 0; self.update_idletasks()

        if self.is_capturing or not self.packet_queue.empty():
            self.after(PROCESSING_INTERVAL_MS, self.process_packet_queue)
        else: # Final update after stopping
             attack_color = ATTACK_LABEL_COLOR if self.model_attacks_detected > 0 else NORMAL_TEXT_COLOR
             self.packet_count_label.configure(text=f"Packets Processed: {self.total_packets_processed}")
             self.attack_count_label.configure(text=f"Model Attacks: {self.model_attacks_detected}", text_color=attack_color)
             print("Finished processing remaining queue.")


    def update_alerts_display(self, new_alerts):
        """ Adds new rule alerts to the deque and updates the textbox. """
        self.alerts_textbox.configure(state="normal")
        updated = False
        for alert in new_alerts:
            self.rule_alerts_list.appendleft(f"[{time.strftime('%H:%M:%S')}] {alert}")
            updated = True
        if updated:
            display_text = "\n".join(self.rule_alerts_list)
            self.alerts_textbox.delete("1.0", "end"); self.alerts_textbox.insert("1.0", display_text)
        self.alerts_textbox.configure(state="disabled")


    def update_attack_details_display(self, attack_details_df):
        """ Adds new model attack details to the deque and Treeview, applying highlighting. """
        if attack_details_df is None or attack_details_df.empty: return
        items_to_insert = []
        for index, row in attack_details_df.iterrows():
            try: ts = pd.to_datetime(row.get('_packet_time', time.time()), unit='s').strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            except: ts = "Invalid Time"
            details = (ts, row.get('_src_ip', 'N/A'), row.get('_src_port', 'N/A'),
                       row.get('_dst_ip', 'N/A'), row.get('_dst_port', 'N/A'),
                       row.get('protocol_type', 'N/A'), row.get('service', 'N/A'),
                       row.get('flag', 'N/A'), row.get('src_bytes', 'N/A'))
            items_to_insert.append(details)
            self.attack_details_list.appendleft(details)

        for item_data in reversed(items_to_insert):
             self.attack_tree.insert("", 0, values=item_data, tags=('attack_row',)) # Tag applies color

        current_items = self.attack_tree.get_children('')
        if len(current_items) > MAX_DISPLAY_ITEMS:
             items_to_delete = current_items[MAX_DISPLAY_ITEMS:]
             self.attack_tree.delete(*items_to_delete)


    def clear_results(self):
        """ Clears displayed results and resets counters/state. """
        self.alerts_textbox.configure(state="normal"); self.alerts_textbox.delete("1.0", "end")
        self.alerts_textbox.configure(state="disabled")
        for item in self.attack_tree.get_children(): self.attack_tree.delete(item)
        self.rule_alerts_list.clear(); self.attack_details_list.clear()
        self.total_packets_processed = 0; self.model_attacks_detected = 0; self.packets_since_last_gui_update = 0
        clear_all_rule_state()
        self.packet_count_label.configure(text="Packets Processed: 0")
        self.attack_count_label.configure(text="Model Attacks: 0", text_color=NORMAL_TEXT_COLOR)
        print("Cleared results and reset anomaly detection state.")


    def on_closing(self):
        """ Handles the window close event gracefully. """
        print("Window close requested.")
        if self.is_capturing:
             if messagebox.askyesno("Confirm Exit", "Capture is running. Stop capture and exit?"):
                 print("Stopping capture before closing..."); self.stop_capture(); time.sleep(0.5)
             else: print("Exit cancelled."); return
        print("Destroying GUI window."); self.destroy()


if __name__ == "__main__":
    # Platform specific info
    if platform.system() == "Windows": print("INFO: Live capture requires Npcap & Admin privileges.")
    elif platform.system() == "Linux": print("INFO: Live capture requires root privileges (sudo).")
    elif platform.system() == "Darwin": print("INFO: Live capture requires root privileges (sudo).")
    else: print(f"INFO: Running on unrecognized OS: {platform.system()}.")

    app = App()
    try: app.mainloop()
    except KeyboardInterrupt: print("\nCtrl+C detected. Closing."); app.on_closing()