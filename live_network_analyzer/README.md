# Live Network Traffic Analyzer

This tool captures network traffic live from a selected interface and analyzes it in near real-time using rule-based anomaly detection and a pre-trained Deep Neural Network (DNN) + Apriori model (based on the NSL-KDD dataset approach). It displays results in a desktop GUI.

**WARNING:**

- **Administrator Privileges Required:** Live packet capture requires elevated (Administrator/root) privileges. Run the script accordingly.
- **Feature Extraction Approximation:** The accuracy of the DNN model on live traffic might be significantly different from its reported accuracy on the NSL-KDD test set. Mapping raw packets to NSL-KDD features is an approximation.
- **Performance:** Processing high-volume traffic in real-time with Python/Scapy can be CPU-intensive and might drop packets on busy networks.

## Features

- Selects a network interface for live capture.
- Captures packets in a separate thread to keep the GUI responsive.
- Applies rule-based detection for potential SYN Floods and Port Scans.
- Uses a pre-trained DNN model (approximating NSL-KDD features) for malicious traffic classification.
- Applies a pre-calculated Apriori rule to filter potential DNN false positives.
- Displays status, packet counts, rule-based alerts, and model-detected attacks in a CustomTkinter GUI.

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
│   └── utils.py           # Helper functions
├── capture_thread.py       # Handles live packet capture thread
├── models/                 # <<< PLACE YOUR TRAINED MODELS HERE >>>
│   ├── dnn_model.h5
│   ├── dnn_preprocessor.joblib
│   └── apriori_rule.pkl
└── README.md              # This file
```

## Setup

1.  **Clone or Download:** Get the project files.
2.  **Place Models:** Copy your trained model files (`dnn_model.h5`), preprocessor (`dnn_preprocessor.joblib`), and Apriori rule (`apriori_rule.pkl`) into the `models/` directory.
3.  **Install Packet Capture Library:**
    - **Windows:** Install **[Npcap](https://npcap.com/)**. Download the latest installer and run it. Make sure to check the "Install Npcap in WinPcap API-compatible Mode" if you need compatibility with older tools, but Scapy generally works well with the native Npcap mode.
    - **Linux:** Install `libpcap-dev` (Debian/Ubuntu: `sudo apt-get update && sudo apt-get install libpcap-dev`) or `libpcap-devel` (Fedora/CentOS: `sudo dnf install libpcap-devel`).
    - **macOS:** Should be included with Xcode Command Line Tools, or install via Homebrew: `brew install libpcap`.
4.  **Install Python Dependencies:**
    - Use a virtual environment (recommended):
      ```bash
      python -m venv venv
      # On Windows:
      venv\Scripts\activate
      # On Linux/macOS:
      source venv/bin/activate
      ```
    - Install packages:
      ```bash
      pip install -r requirements.txt
      ```

## Running the Application

1.  **Activate Virtual Environment** (if used).
2.  **Run as Administrator/root:**
    - **Windows:** Right-click your terminal (Command Prompt, PowerShell, etc.) or IDE and select "Run as administrator". Navigate to the project directory and run the script.
    - **Linux/macOS:** Use `sudo`:
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

- **Requires Admin/root privileges.**
- **Feature Mapping Inaccuracy:** The core limitation mentioned before still applies.
- **Performance:** May struggle on networks with very high packet rates. Packet drops are possible.
- **Memory Usage:** Storing raw packets in the queue (even temporarily) can consume memory. Processing batches helps mitigate this.
- **GUI Responsiveness:** If processing takes too long, the GUI might still lag slightly between updates. Adjust `PROCESSING_INTERVAL_MS` or the batch size in `main_gui.py` if needed.
- **Error Handling:** Basic error handling is included, but complex network or model issues might require more specific debugging. Check the console output for errors.
