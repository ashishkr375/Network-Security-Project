# live_network_analyzer/main_gui.py
import customtkinter as ctk
from tkinter import ttk, messagebox # Use standard tkinter messagebox
import queue
import threading
import time
import platform
import pandas as pd
import numpy as np
from collections import deque
import os
import traceback # For detailed error logging in GUI thread

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
MAX_PACKETS_IN_QUEUE = 2000
PROCESSING_INTERVAL_MS = 300
GUI_UPDATE_BATCH_SIZE = 50
MAX_DISPLAY_ITEMS = 150
CAPTURE_DURATION_SECONDS = 60 # <<< Fixed capture duration >>>

# --- UI Color Definitions ---
ATTACK_ROW_BG_COLOR = ("#FFD2D2", "#6B0000") # Light red (light), Dark red (dark)
ATTACK_ROW_FG_COLOR = ("black", "white")    # Black text (light), White text (dark)
NORMAL_TEXT_COLOR = ("black", "white")      # Default text color (dark, light)
ATTACK_LABEL_COLOR = ("red", "coral")       # Color for attack counter text (dark, light)
STATUS_CAPTURING_COLOR = ("#006400", "#90EE90") # Dark green (light), Light green (dark)
STATUS_ERROR_COLOR = ("red", "coral")
STATUS_STOPPING_COLOR = ("#FFA500", "#FFD700") # Orange (light), Gold (dark)

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(APP_TITLE)
        self.geometry("1000x800")
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
        self.interfaces_map = {} # Store mapping of display name to interface ID
        self.capture_stop_timer = None # Holds the ID for the self.after timer

        # --- Load Predictor ---
        self.predictor = None
        if not os.path.exists(MODEL_DIR):
             print(f"ERROR: Models directory '{MODEL_DIR}' not found.")
             messagebox.showerror("Initialization Error", f"Models directory '{MODEL_DIR}' not found.\nPlease create it and place model files inside.")
        else:
            try:
                self.predictor = TrafficPredictor(model_dir=MODEL_DIR)
                # Add a check if models actually loaded (assuming predictor has a flag/property)
                # Example: if not self.predictor.models_loaded: raise ValueError("Models not loaded")
                print("Predictor initialized successfully.")
            except Exception as e:
                print(f"ERROR during TrafficPredictor initialization: {e}")
                traceback.print_exc()
                messagebox.showerror("Initialization Error", f"Failed to initialize predictor: {e}\nPrediction disabled.")
                self.predictor = None # Ensure it's None if failed

        # --- UI Elements ---
        self.create_widgets()
        self.populate_interfaces()

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        """ Creates and arranges all the GUI elements. """
        self.grid_columnconfigure(0, weight=1) # Make main column expandable
        self.grid_rowconfigure(2, weight=1)    # Make results row expandable

        # --- Top Frame: Controls ---
        self.controls_frame = ctk.CTkFrame(self)
        self.controls_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.controls_frame.grid_columnconfigure(1, weight=1) # Make combobox expand

        self.if_label = ctk.CTkLabel(self.controls_frame, text="Network Interface:")
        self.if_label.grid(row=0, column=0, padx=(10, 5), pady=10, sticky="w")
        self.if_combobox = ctk.CTkComboBox(self.controls_frame, state="readonly", values=["Fetching..."], command=self.interface_selected)
        self.if_combobox.grid(row=0, column=1, padx=5, pady=10, sticky="ew")
        self.start_button = ctk.CTkButton(self.controls_frame, text=f"Start Capture ({CAPTURE_DURATION_SECONDS}s)", command=self.start_capture, width=140) # Updated text
        self.start_button.grid(row=0, column=2, padx=5, pady=10)
        self.stop_button = ctk.CTkButton(self.controls_frame, text="Stop Capture", command=self.manual_stop_capture, state="disabled", width=120) # Renamed command
        self.stop_button.grid(row=0, column=3, padx=(5, 10), pady=10)

        # --- Middle Frame: Status & Counts ---
        self.status_frame = ctk.CTkFrame(self)
        self.status_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="ew")
        self.status_frame.grid_columnconfigure(3, weight=1) # Push clear button right

        self.status_label = ctk.CTkLabel(self.status_frame, text="Status: Idle", anchor="w", width=400) # Increased width
        self.status_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.packet_count_label = ctk.CTkLabel(self.status_frame, text="Packets Processed: 0", anchor="w")
        self.packet_count_label.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        self.attack_count_label = ctk.CTkLabel(self.status_frame, text="Model Attacks: 0", anchor="w", text_color=NORMAL_TEXT_COLOR)
        self.attack_count_label.grid(row=0, column=2, padx=10, pady=5, sticky="w")
        self.clear_button = ctk.CTkButton(self.status_frame, text="Clear Results", command=self.clear_results, width=110)
        self.clear_button.grid(row=0, column=3, padx=10, pady=5, sticky="e")

        # --- Bottom Frame: Results Tabs ---
        self.results_notebook = ctk.CTkTabview(self)
        self.results_notebook.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.results_notebook.add("Rule Alerts")
        self.results_notebook.add("Model Attack Details")
        self.results_notebook.set("Rule Alerts") # Start on alerts tab

        # --- Rule Alerts Tab Content ---
        alerts_tab = self.results_notebook.tab("Rule Alerts")
        alerts_tab.grid_columnconfigure(0, weight=1); alerts_tab.grid_rowconfigure(0, weight=1)
        self.alerts_textbox = ctk.CTkTextbox(alerts_tab, state="disabled", wrap="word", activate_scrollbars=True)
        self.alerts_textbox.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        # --- Attack Details Tab Content (Treeview) ---
        attack_tab = self.results_notebook.tab("Model Attack Details")
        attack_tab.grid_columnconfigure(0, weight=1); attack_tab.grid_rowconfigure(0, weight=1)

        # Treeview Styling (Needs self for _apply_appearance_mode)
        style = ttk.Style(self) # Pass self to style
        current_mode = ctk.get_appearance_mode()
        mode_index = 1 if current_mode == "Dark" else 0 # 0=light, 1=dark

        # Use CTk theme values for more consistency
        try:
            tree_bg = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkTextbox"]["fg_color"])
            tree_fg = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkLabel"]["text_color"])
            heading_bg = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkButton"]["fg_color"]) # Use button background
            heading_text = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkButton"]["text_color"])
            selected_color = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkButton"]["hover_color"]) # Use hover for selection
        except Exception as e: # Fallback if theme keys missing
             print(f"Warning: Error getting theme colors, using fallbacks. {e}")
             tree_bg = "#F0F0F0" if mode_index == 0 else "#303030"
             tree_fg = "black" if mode_index == 0 else "white"
             heading_bg = "#D0D0D0" if mode_index == 0 else "#505050"
             heading_text = tree_fg
             selected_color = "#A0A0FF" if mode_index == 0 else "#000080"


        style.theme_use('default') # Start from default to avoid conflicts
        style.configure("Treeview", background=tree_bg, foreground=tree_fg, fieldbackground=tree_bg, borderwidth=1, rowheight=25)
        style.map('Treeview', background=[('selected', selected_color)], foreground=[('selected', heading_text)])
        style.configure("Treeview.Heading", background=heading_bg, foreground=heading_text, relief="flat", font=('Segoe UI', 10, 'bold'), padding=(5, 5))
        style.map("Treeview.Heading", background=[('active', heading_bg)]) # No visual change on hover needed


        tree_columns = ("Time", "SrcIP", "SrcPort", "DstIP", "DstPort", "Proto", "Service", "Flag", "Bytes")
        self.attack_tree = ttk.Treeview(
            attack_tab,
            columns=tree_columns,
            show="headings",
            style="Treeview",
            selectmode="browse" # Only allow single row selection
        )
        self.attack_tree.grid(row=0, column=0, padx=(5,0), pady=5, sticky="nsew")

        # Configure Treeview Tag for highlighting attack rows
        attack_bg = self._apply_appearance_mode(ATTACK_ROW_BG_COLOR)
        attack_fg = self._apply_appearance_mode(ATTACK_ROW_FG_COLOR)
        self.attack_tree.tag_configure('attack_row', background=attack_bg, foreground=attack_fg)

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
        self.attack_tree.column("Bytes", width=80, anchor='e', stretch=True) # Allow last column to stretch

        # Scrollbar (use CTkScrollbar for consistency)
        tree_scrollbar = ctk.CTkScrollbar(attack_tab, command=self.attack_tree.yview)
        tree_scrollbar.grid(row=0, column=1, padx=(0,5), pady=5, sticky="ns")
        self.attack_tree.configure(yscrollcommand=tree_scrollbar.set)

        # Ensure the predictor loaded message is visible if error occurred
        if self.predictor is None:
            self.status_label.configure(text="Status: ERROR - Predictor/Models failed to load.", text_color=STATUS_ERROR_COLOR)

    def interface_selected(self, choice):
        """ Handles selection change in the interface combobox. (Optional) """
        print(f"Interface selected: {choice}")
        # Can add validation or updates here if needed when selection changes


    def populate_interfaces(self):
        """ Fetches and displays available network interfaces. """
        self.status_label.configure(text="Status: Fetching interfaces...")
        self.if_combobox.configure(values=["Fetching..."], state="disabled")
        self.start_button.configure(state="disabled")
        self.update_idletasks() # Force GUI update

        try:
            interfaces = capture_thread.get_interfaces()
            self.interfaces_map.clear() # Clear previous map
            valid_interfaces_found = False
            display_names = []

            for iface in interfaces:
                 # Ensure interface has both display name and a valid ID
                 if isinstance(iface, dict) and iface.get("display") and iface.get("id"):
                     display = iface["display"]
                     id_val = iface["id"]
                     self.interfaces_map[display] = id_val
                     display_names.append(display)
                     valid_interfaces_found = True
                 else:
                      print(f"Skipping invalid interface entry: {iface}")

            if valid_interfaces_found:
                self.if_combobox.configure(values=display_names, state="readonly")
                self.if_combobox.set(display_names[0]) # Select first valid one
                self.status_label.configure(text="Status: Idle", text_color=NORMAL_TEXT_COLOR)
                self.start_button.configure(state="normal") # Enable start button
            else:
                # Handle case where get_interfaces() returned list but no valid entries
                fallback_msg = "No suitable interfaces found"
                if interfaces and interfaces[0].get("display"): # Use message from get_interfaces if available
                    fallback_msg = interfaces[0]["display"]
                self.if_combobox.configure(values=[fallback_msg], state="disabled")
                self.if_combobox.set(fallback_msg)
                self.start_button.configure(state="disabled")
                self.status_label.configure(text=f"Status: Error - {fallback_msg}", text_color="orange")

        except Exception as e:
            print(f"ERROR during interface population: {e}")
            traceback.print_exc()
            self.status_label.configure(text="Status: Error fetching interfaces", text_color=STATUS_ERROR_COLOR)
            self.if_combobox.configure(values=["Error fetching interfaces"], state="disabled")
            self.if_combobox.set("Error fetching interfaces")
            self.start_button.configure(state="disabled")


    def start_capture(self):
        """ Starts packet capture on the selected interface. """
        if self.is_capturing:
            print("Warning: Capture already in progress.")
            return

        selected_display = self.if_combobox.get()
        if not selected_display or selected_display not in self.interfaces_map:
            self.status_label.configure(text="Status: No valid interface selected", text_color=STATUS_ERROR_COLOR)
            return

        interface_id = self.interfaces_map[selected_display]
        print(f"Attempting to start capture on interface ID: '{interface_id}' for {CAPTURE_DURATION_SECONDS} seconds.")

        try:
            # Clear previous results first
            self.clear_results()
            
            # Create and start the capture thread
            self.packet_queue = queue.Queue(maxsize=MAX_PACKETS_IN_QUEUE)
            self.capture_thread_instance = capture_thread.CaptureThread(
                packet_queue=self.packet_queue,
                interface_id=interface_id,
                packet_count=0,  # No packet limit, we use time
                stop_timeout=0.5  # Shorter timeout for more responsive stopping
            )
            
            # Update UI state
            self.is_capturing = True
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
            self.if_combobox.configure(state="disabled")
            self.clear_button.configure(state="disabled")
            
            # Start the capture thread
            self.capture_thread_instance.start()
            
            # Wait briefly for capture to be ready
            self.status_label.configure(
                text="Status: Initializing capture...",
                text_color=STATUS_CAPTURING_COLOR
            )
            self.update_idletasks()
            
            # Schedule the automatic stop
            if self.capture_stop_timer:
                self.after_cancel(self.capture_stop_timer)
            self.capture_stop_timer = self.after(CAPTURE_DURATION_SECONDS * 1000, self._auto_stop_capture)
            
            # Start status updates after a short delay
            self.after(100, self._update_capture_status)
            
            # Start processing packets
            self.process_packet_queue()

        except Exception as e:
            print(f"ERROR starting capture: {e}")
            traceback.print_exc()
            self.status_label.configure(
                text=f"Status: Error starting capture - {str(e)}",
                text_color=STATUS_ERROR_COLOR
            )
            self._stop_capture_logic("error")

    def _update_capture_status(self):
        """ Updates the status label with remaining capture time. """
        if not self.is_capturing:
            return
            
        try:
            if not self.capture_thread_instance or not self.capture_thread_instance.is_alive():
                print("Capture thread not alive during status update")
                self._stop_capture_logic("ended_unexpectedly")
                return
                
            current_time = time.time()
            elapsed = current_time - self.capture_thread_instance.capture_start_time
            remaining = max(0, CAPTURE_DURATION_SECONDS - elapsed)
            
            if remaining > 0:
                self.status_label.configure(
                    text=f"Status: Capturing... ({int(remaining)}s remaining)",
                    text_color=STATUS_CAPTURING_COLOR
                )
                self.after(1000, self._update_capture_status)  # Update every second
            else:
                self._auto_stop_capture()
                
        except Exception as e:
            print(f"Error updating capture status: {e}")
            traceback.print_exc()
            self._stop_capture_logic("error")

    def _stop_capture_logic(self, reason="manual"):
        """ Internal method to handle capture stopping logic. """
        if not self.is_capturing:
            return

        print(f"Initiating stop capture ({reason})...")
        if self.capture_stop_timer:
            print("Cancelling pending automatic stop timer.")
            self.after_cancel(self.capture_stop_timer)
            self.capture_stop_timer = None

        # Stop the capture thread if it exists and is alive
        if self.capture_thread_instance and self.capture_thread_instance.is_alive():
            print("Stopping capture thread...")
            self.capture_thread_instance.stop()
            # Give the thread a moment to stop gracefully
            self.capture_thread_instance.join(timeout=2.0)
        else:
            print("Capture thread instance not found or not alive when stopping.")

        # Update UI state
        self.is_capturing = False
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.if_combobox.configure(state="readonly")
        self.clear_button.configure(state="normal")

        # Update status based on reason
        status_text = "Status: "
        if reason == "manual":
            status_text += "Capture stopped manually"
        elif reason == "timeout":
            status_text += f"Capture completed ({CAPTURE_DURATION_SECONDS}s)"
        elif reason == "error":
            status_text += "Capture stopped due to error"
        elif reason == "ended_unexpectedly":
            status_text += "Capture ended unexpectedly"
        
        self.status_label.configure(
            text=status_text,
            text_color=NORMAL_TEXT_COLOR if reason != "error" else STATUS_ERROR_COLOR
        )

        print(f"Capture stop signaled ({reason}). Processing remaining queue...")
        # Process any remaining packets in the queue
        self.process_packet_queue()

    def manual_stop_capture(self):
        """ User-initiated capture stop. """
        self._stop_capture_logic("manual")

    def _auto_stop_capture(self):
        """ Automatic capture stop after duration expires. """
        print(f"Auto-stopping capture after {CAPTURE_DURATION_SECONDS} seconds")
        self._stop_capture_logic("timeout")


    def process_packet_queue(self):
        """ Process packets from the queue and update the display. """
        if not self.is_capturing and self.packet_queue.empty():
            print("Processing queue finished after capture stop.")
            return

        # Process up to GUI_UPDATE_BATCH_SIZE packets at once
        packets_in_batch = []
        try:
            for _ in range(GUI_UPDATE_BATCH_SIZE):
                if self.packet_queue.empty(): break
                packet_or_signal = self.packet_queue.get_nowait()
                
                # Handle control signals from capture thread
                if isinstance(packet_or_signal, str):
                    self.handle_capture_signal(packet_or_signal)
                    continue
                    
                packets_in_batch.append(packet_or_signal)
                
        except queue.Empty:
            pass  # Queue emptied during processing
            
        # Process the collected packets
        if packets_in_batch:
            try:
                print(f"\nProcessing batch of {len(packets_in_batch)} raw packets...")
                
                # Extract features from the batch of packets
                features_list = [extract_features_from_packet(packet) for packet in packets_in_batch]
                features_list = [f for f in features_list if f is not None]  # Filter out None results
                
                if features_list:
                    print(f"Successfully extracted features from {len(features_list)} packets")
                    feature_df = pd.DataFrame(features_list)
                    
                    # Ensure all required columns exist
                    missing_columns = [col for col in KDD_COLUMNS if col not in feature_df.columns]
                    if missing_columns:
                        print(f"Adding missing columns: {missing_columns}")
                        for col in missing_columns:
                            feature_df[col] = 0
                    
                    # Update total packet count and update UI
                    self.total_packets_processed += len(features_list)
                    
                    # Check for rule-based anomalies first for immediate alerting
                    print("Checking for rule-based anomalies...")
                    new_alerts = check_anomalies(feature_df)
                    if new_alerts:
                        print(f"Found {len(new_alerts)} new rule alerts!")
                        # Update display immediately
                        self.update_alerts_display(new_alerts)
                    
                    # Run model prediction if available
                    if self.predictor and hasattr(self.predictor, 'predict_traffic') and hasattr(self.predictor, 'is_loaded') and self.predictor.is_loaded:
                        print("Running model prediction...")
                        try:
                            model_predictions = self.predictor.predict_traffic(feature_df)
                            if model_predictions is not None and len(model_predictions) > 0:
                                attack_indices = [i for i, pred in enumerate(model_predictions) if pred == 1]
                                if attack_indices:
                                    print(f"Model detected {len(attack_indices)} attacks in this batch")
                                    self.model_attacks_detected += len(attack_indices)
                                    attack_details_batch_df = feature_df.iloc[attack_indices].copy()
                                    self.update_attack_details_display(attack_details_batch_df)
                                else:
                                    print("Model found no attacks in this batch")
                        except Exception as e:
                            print(f"Error during prediction: {e}")
                            traceback.print_exc()

                # Update GUI with counts
                self.packet_count_label.configure(text=f"Packets Processed: {self.total_packets_processed}")
                
                # Update attack count with appropriate color
                if self.model_attacks_detected > 0:
                    self.attack_count_label.configure(
                        text=f"Model Attacks: {self.model_attacks_detected}",
                        text_color=self._apply_appearance_mode(ATTACK_LABEL_COLOR)
                    )
                else:
                    self.attack_count_label.configure(
                        text=f"Model Attacks: {self.model_attacks_detected}",
                        text_color=self._apply_appearance_mode(NORMAL_TEXT_COLOR)
                    )
                    
                # Force immediate GUI updates
                self.update_idletasks()

            except Exception as e:
                print(f"ERROR during batch processing: {e}")
                traceback.print_exc()

        # Schedule next update if still capturing or queue not empty
        if self.is_capturing or not self.packet_queue.empty():
            self.after(PROCESSING_INTERVAL_MS, self.process_packet_queue)
        else:
            print("Finished processing packet queue.")
            # Final UI update
            self.packet_count_label.configure(text=f"Packets Processed: {self.total_packets_processed}")

    def update_alerts_display(self, new_alerts):
        """ Adds new rule alerts to the deque and updates the textbox with enhanced visibility. """
        if not new_alerts:
            return
        
        print(f"Updating alerts display with {len(new_alerts)} new alerts")
        
        # Force window to front
        self.lift()
        
        # Force the alerts textbox to be enabled for editing
        self.alerts_textbox.configure(state="normal")
        
        # Add alerts with enhanced formatting for better visibility
        for alert in reversed(new_alerts):
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Format alerts with visual indicators based on type
            if "SYN Flood" in alert:
                # Format with emphasis and directional arrow
                parts = alert.split("from ")
                if len(parts) > 1:
                    attacker_victim = parts[1].split(" (")[0]
                    if " to " in attacker_victim:
                        attacker, victim = attacker_victim.split(" to ")
                        count_part = parts[1].split("(")[1]
                        formatted_alert = f"🚨 SYN FLOOD ATTACK  [{timestamp}]\n"
                        formatted_alert += f"   Source: {attacker} → Target: {victim}\n"
                        formatted_alert += f"   Details: ({count_part}\n"
                    else:
                        formatted_alert = f"🚨 SYN FLOOD ATTACK  [{timestamp}]\n"
                        formatted_alert += f"   From: {attacker_victim}\n"
                        formatted_alert += f"   Details: ({parts[1].split('(')[1]}\n"
                else:
                    formatted_alert = f"🚨 {alert}  [{timestamp}]\n"
            elif "Port Scan" in alert:
                # Format with scanning indicator
                parts = alert.split("from ")
                if len(parts) > 1:
                    scanner_target = parts[1].split(" (")[0]
                    if " to " in scanner_target:
                        scanner, target = scanner_target.split(" to ")
                        count_part = parts[1].split("(")[1]
                        formatted_alert = f"🔍 PORT SCAN DETECTED  [{timestamp}]\n"
                        formatted_alert += f"   Scanner: {scanner} → Target: {target}\n"
                        formatted_alert += f"   Details: ({count_part}\n"
                    else:
                        formatted_alert = f"🔍 PORT SCAN DETECTED  [{timestamp}]\n"
                        formatted_alert += f"   From: {scanner_target}\n"
                        formatted_alert += f"   Details: ({parts[1].split('(')[1]}\n"
                else:
                    formatted_alert = f"🔍 {alert}  [{timestamp}]\n"
            else:
                # Default formatting for other alerts
                formatted_alert = f"⚠️ {alert}  [{timestamp}]\n"
                
            # Add a separator line for better readability
            formatted_alert += "────────────────────────────────────────────────────\n"
            
            # Add to internal storage and update the display
            self.rule_alerts_list.appendleft(formatted_alert)
            self.alerts_textbox.insert("1.0", formatted_alert)
            
        # Ensure alerts tab is visible and selected
        self.results_notebook.set("Rule Alerts")
        
        # Limit number of displayed alerts for performance
        while len(self.rule_alerts_list) > MAX_DISPLAY_ITEMS:
            self.rule_alerts_list.pop()
        
        # Make sure alerts textbox is showing most recent content
        self.alerts_textbox.see("1.0")
        
        # Disable editing and update count
        self.alerts_textbox.configure(state="disabled")
        
        # Update alerts count in status bar
        self.attack_count_label.configure(
            text=f"Rule Alerts: {len(self.rule_alerts_list)}",
            text_color=self._apply_appearance_mode(ATTACK_LABEL_COLOR)
        )
        
        # Force UI update immediately
        self.update_idletasks()


    def update_attack_details_display(self, attack_details_df):
        """ Adds new model attack details to the deque and Treeview, applying highlighting. """
        if attack_details_df is None or attack_details_df.empty: return

        items_to_insert = [] # Collect items before inserting
        for index, row in attack_details_df.iterrows():
            try: ts = pd.to_datetime(row.get('_packet_time', time.time()), unit='s').strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            except Exception as time_e: print(f"Time formatting error: {time_e}"); ts = "Invalid Time"

            # Ensure all values are strings for display
            details = (
                str(ts),
                str(row.get('_src_ip', 'N/A')), str(row.get('_src_port', 'N/A')),
                str(row.get('_dst_ip', 'N/A')), str(row.get('_dst_port', 'N/A')),
                str(row.get('protocol_type', 'N/A')), str(row.get('service', 'N/A')),
                str(row.get('flag', 'N/A')), str(row.get('src_bytes', 'N/A'))
            )
            items_to_insert.append(details)
            self.attack_details_list.appendleft(details) # Add to internal deque

        # Insert items into the Treeview (newest at the top)
        for item_data in reversed(items_to_insert): # Insert collected items
             self.attack_tree.insert("", 0, values=item_data, tags=('attack_row',)) # Tag applies color

        # Limit items displayed in Treeview for performance
        current_items = self.attack_tree.get_children('')
        if len(current_items) > MAX_DISPLAY_ITEMS:
             items_to_delete = current_items[MAX_DISPLAY_ITEMS:]
             self.attack_tree.delete(*items_to_delete) # Delete oldest items


    def clear_results(self):
        """ Clears displayed results and resets counters/state. """
        print("Clearing results...")
        # Clear GUI elements
        self.alerts_textbox.configure(state="normal")
        self.alerts_textbox.delete("1.0", "end")
        self.alerts_textbox.configure(state="disabled")
        for item in self.attack_tree.get_children(): self.attack_tree.delete(item)

        # Clear internal state
        self.rule_alerts_list.clear()
        self.attack_details_list.clear()
        self.total_packets_processed = 0
        self.model_attacks_detected = 0
        self.packets_since_last_gui_update = 0
        clear_all_rule_state() # Clear state in anomaly detector module

        # Update counters display
        self.packet_count_label.configure(text="Packets Processed: 0")
        self.attack_count_label.configure(text="Model Attacks: 0", text_color=NORMAL_TEXT_COLOR)
        print("Cleared results and reset anomaly detection state.")


    def on_closing(self):
        """ Handles the window close event gracefully. """
        print("Window close requested.")
        if self.is_capturing:
             # Ask for confirmation only if capture is active
             if messagebox.askyesno("Confirm Exit", "Capture is running. Stop capture and exit?"):
                 print("Stopping capture before closing...")
                 # Use manual stop logic which cancels timer and signals thread
                 self.manual_stop_capture()
                 # Give thread a moment to process stop signal before destroying window
                 time.sleep(0.6) # Increased slightly
             else:
                 print("Exit cancelled by user.")
                 return # Don't destroy window if user cancels

        print("Destroying GUI window.")
        self.destroy()

    def handle_capture_signal(self, signal):
        """ Handles control signals from the capture thread. """
        print(f"GUI received signal: {signal}")
        
        if signal.startswith("CAPTURE_ERROR"):
            error_detail = signal.split(":", 1)[-1].strip()
            full_error_msg = f"Status: Capture ERROR - {error_detail}."
            print(f"Capture thread reported error: {error_detail}")
            self.status_label.configure(text=full_error_msg, text_color=STATUS_ERROR_COLOR)
            messagebox.showerror("Capture Error", 
                               f"Packet capture failed:\n{error_detail}\n\nCheck console, permissions, and Npcap installation.")
            if self.is_capturing:
                self._stop_capture_logic(reason="error")
                
        elif signal == "CAPTURE_ENDED_UNEXPECTEDLY":
            print("Capture thread ended unexpectedly.")
            self.status_label.configure(text="Status: Capture ended unexpectedly.", text_color="orange")
            if self.is_capturing:
                self._stop_capture_logic(reason="ended_unexpectedly")
                
        elif signal == "CAPTURE_THREAD_EXITED":
            print("Capture thread run() method has exited.")
            if self.is_capturing:
                print("Forcing capture stop as thread exited while GUI expected capture.")
                self._stop_capture_logic(reason="thread_exited")
                
        else:
            print(f"Unknown signal received: {signal}")


if __name__ == "__main__":
    # Platform specific info messages
    if platform.system() == "Windows": print("INFO: Live capture requires Npcap & Admin privileges.")
    elif platform.system() == "Linux": print("INFO: Live capture requires root privileges (sudo).")
    elif platform.system() == "Darwin": print("INFO: Live capture requires root privileges (sudo).")
    else: print(f"INFO: Running on unrecognized OS: {platform.system()}. Capture might not work.")

    # Create and run the application
    app = App()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        print("\nCtrl+C detected. Closing application.")
        app.on_closing() # Attempt graceful shutdown on Ctrl+C