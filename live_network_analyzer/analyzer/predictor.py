# analyzer/predictor.py
import tensorflow as tf
import joblib
import pickle
import pandas as pd
import numpy as np
import os
# *** Corrected Import: Only import from OTHER modules within analyzer ***
from .packet_parser import KDD_COLUMNS # Import column list for consistency

# Define features needed for Apriori rule matching (must match training names)
DISCRETE_FEATURES_APRIORI = [
    'protocol_type', 'service', 'flag', 'land', 'logged_in',
    'root_shell', 'su_attempted', 'is_host_login', 'is_guest_login'
]

# Increased threshold for attack detection - helps reduce false positives
DEFAULT_PREDICTION_THRESHOLD = 0.5


class TrafficPredictor:
    """ Handles loading models and making predictions on traffic data. """
    def __init__(self, model_dir="models"):
        """ Loads artifacts during initialization. """
        # Initialize is_loaded attribute first
        self.is_loaded = False
        # --- End Initialization ---

        self.model_path = os.path.join(model_dir, "dnn_model.h5")
        self.preprocessor_path = os.path.join(model_dir, "dnn_preprocessor.joblib")
        self.rule_path = os.path.join(model_dir, "apriori_rule.pkl")
        self.model = None
        self.preprocessor = None
        self.apriori_rule_antecedents = None
        self._load_artifacts() # Call loading method

    def _load_artifacts(self):
        """ Loads the trained model, preprocessor, and Apriori rule. """
        print("Loading prediction artifacts...")
        # Keep track of loading success for each component
        model_ok = False
        preprocessor_ok = False
        rule_ok = False # Rule loading is optional for the 'is_loaded' flag

        try:
            # Load model without compiling for faster prediction setup
            self.model = tf.keras.models.load_model(self.model_path, compile=False)
            print(f"Loaded DNN model from {self.model_path}")
            model_ok = True
        except Exception as e:
            print(f"ERROR loading DNN model '{self.model_path}': {e}")
            # Don't raise here, let initialization complete as much as possible

        try:
            self.preprocessor = joblib.load(self.preprocessor_path)
            print(f"Loaded DNN preprocessor from {self.preprocessor_path}")
            preprocessor_ok = True
        except Exception as e:
            print(f"ERROR loading preprocessor '{self.preprocessor_path}': {e}")

        try:
            with open(self.rule_path, 'rb') as f:
                self.apriori_rule_antecedents = pickle.load(f)
            # Basic validation of the loaded rule
            if not isinstance(self.apriori_rule_antecedents, (set, frozenset)):
                print(f"WARNING: Loaded Apriori rule from '{self.rule_path}' is not a set/frozenset "
                      f"(type: {type(self.apriori_rule_antecedents)}). Filtering will be skipped.")
                self.apriori_rule_antecedents = None # Invalidate rule
            elif len(self.apriori_rule_antecedents) == 0:
                print(f"WARNING: Loaded Apriori rule from '{self.rule_path}' is empty. Filtering will be skipped.")
                self.apriori_rule_antecedents = None # Invalidate rule
            else:
                print(f"Loaded Apriori rule from {self.rule_path}")
                print(f"  Rule Antecedents: {self.apriori_rule_antecedents}")
                rule_ok = True # Consider rule loaded successfully if valid type and not empty
        except FileNotFoundError:
             print(f"INFO: Apriori rule file not found at '{self.rule_path}'. Filtering will be skipped.")
             self.apriori_rule_antecedents = None
        except Exception as e:
            print(f"ERROR loading Apriori rule '{self.rule_path}': {e}. Filtering will be skipped.")
            self.apriori_rule_antecedents = None

        # Set the overall loaded status based on essential components
        self.is_loaded = model_ok and preprocessor_ok
        # --- End Setting Status ---

        if self.is_loaded:
            print("Prediction artifacts (model & preprocessor) loaded successfully.")
        else:
             print("ERROR: Failed to load essential prediction artifacts (model or preprocessor). Predictions disabled.")


    def predict_traffic(self, features_df, threshold=DEFAULT_PREDICTION_THRESHOLD):
        """
        Predicts traffic using DNN and applies Apriori filtering if rule loaded.
        Assumes features_df contains the KDD_COLUMNS + metadata columns (_*).
        Returns predictions (0=Normal, 1=Attack) as a numpy array, or None on error.
        """
        if not self.is_loaded:
            print("Predictor not fully loaded. Skipping prediction.")
            return None # Indicate failure or inability to predict

        if features_df.empty:
            return np.array([]) # Return empty array for empty input

        # SYN Flood detection enhancement: Explicitly mark TCP SYN packets as attacks
        # This ensures TCP SYN floods are always detected by the model
        syn_flood_indices = (features_df['protocol_type'] == 'tcp') & (features_df['flag'] == 'S0')
        if syn_flood_indices.any():
            print(f"Found {sum(syn_flood_indices)} SYN packets that will be marked as attacks")
            
        # --- Prepare data for Apriori matching (uses original discrete features) ---
        apriori_sets = []
        # Only prepare if rule is valid and loaded
        if self.apriori_rule_antecedents is not None:
            apriori_match_data = pd.DataFrame()
            missing_apriori_cols = []
            for col in DISCRETE_FEATURES_APRIORI:
                if col in features_df.columns:
                    # Format as 'column_name=value' strings, handle potential NaN/None
                    apriori_match_data[col] = col + '=' + features_df[col].fillna('NA').astype(str)
                else:
                    missing_apriori_cols.append(col)
            if missing_apriori_cols:
                print(f"Warning: Discrete features missing for Apriori: {missing_apriori_cols}")

            # Convert each row into a set of 'feature=value' strings for efficient checking
            if not apriori_match_data.empty:
                apriori_sets = apriori_match_data.apply(lambda row: set(row.dropna()), axis=1).tolist()
            else: # If no relevant columns found
                 apriori_sets = [set() for _ in range(len(features_df))] # List of empty sets

        # --- Prepare data for DNN prediction (uses the full KDD feature set) ---
        try:
            # Ensure columns are in the exact order expected by the preprocessor
            # Select only the KDD columns required for the model
            dnn_input_df = features_df[KDD_COLUMNS].copy()
            # Print summary of input data for debugging
            print(f"Input data shape: {dnn_input_df.shape}, Protocol types: {dnn_input_df['protocol_type'].value_counts().to_dict()}")
        except KeyError as e:
             print(f"ERROR: Missing required KDD column for DNN prediction: {e}")
             return None # Cannot proceed without all required columns

        # Preprocess using the loaded preprocessor
        try:
            X_processed = self.preprocessor.transform(dnn_input_df)
        except ValueError as e:
             print(f"ERROR during preprocessing: {e}")
             print("This might be due to unexpected data types or unseen values in categorical features.")
             print("Input DataFrame dtypes:\n", dnn_input_df.dtypes)
             return None
        except Exception as e:
             print(f"ERROR during preprocessing: {e}")
             return None

        # --- Make initial DNN predictions ---
        try:
            # Use verbose=0 to reduce console noise during live capture
            dnn_predictions_prob = self.model.predict(X_processed, verbose=0)
            dnn_predictions = (dnn_predictions_prob > threshold).astype(int).flatten()
            print(f"Model predicted {np.sum(dnn_predictions)} attacks out of {len(dnn_predictions)} packets")
        except Exception as e:
            print(f"ERROR during model prediction: {e}")
            return None

        # --- Apply heuristic rules to enhance model predictions ---
        final_predictions = dnn_predictions.copy()
        
        # Force-mark TCP SYN packets as attacks (ensures SYN flood detection)
        if syn_flood_indices.any():
            final_predictions[syn_flood_indices] = 1
            print(f"Marked {sum(syn_flood_indices)} SYN packets as attacks")
            
        # --- Apply Apriori Filtering (if rule is valid and data prepared) ---
        if self.apriori_rule_antecedents is not None and len(apriori_sets) == len(final_predictions):
            filtered_count = 0
            attack_indices = np.where(final_predictions == 1)[0] # Indices where predicted attack

            for idx in attack_indices:
                # Check if the items defining the 'normal' rule are present in this packet's features
                if idx < len(apriori_sets) and self.apriori_rule_antecedents.issubset(apriori_sets[idx]):
                    final_predictions[idx] = 0  # Override 'attack' to 'normal' based on rule
                    filtered_count += 1

            if filtered_count > 0: 
                print(f"Apriori filtered {filtered_count} predictions.")
        elif self.apriori_rule_antecedents is not None: # Log mismatch only if rule exists
            print(f"Warning: Apriori sets ({len(apriori_sets)}) length mismatch with predictions ({len(final_predictions)}). Skipping filter.")

        # Print final prediction summary
        attack_count = np.sum(final_predictions)
        if attack_count > 0:
            print(f"Final prediction: {attack_count} attacks detected")
            
        return final_predictions