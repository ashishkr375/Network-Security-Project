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

# ADJUST THIS THRESHOLD TO REDUCE FALSE POSITIVES
DEFAULT_PREDICTION_THRESHOLD = 0.85


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
            self.model = tf.keras.models.load_model(self.model_path, compile=False)
            print(f"Loaded DNN model from {self.model_path}")
            model_ok = True
        except Exception as e: print(f"ERROR loading DNN model '{self.model_path}': {e}")
        try:
            self.preprocessor = joblib.load(self.preprocessor_path)
            print(f"Loaded DNN preprocessor from {self.preprocessor_path}")
            preprocessor_ok = True
        except Exception as e: print(f"ERROR loading preprocessor '{self.preprocessor_path}': {e}")
        try:
            with open(self.rule_path, 'rb') as f: self.apriori_rule_antecedents = pickle.load(f)
            if not isinstance(self.apriori_rule_antecedents, (set, frozenset)):
                print(f"WARNING: Loaded Apriori rule from '{self.rule_path}' is not a set/frozenset. Filtering skipped.")
                self.apriori_rule_antecedents = None
            elif len(self.apriori_rule_antecedents) == 0:
                print(f"WARNING: Loaded Apriori rule from '{self.rule_path}' is empty. Filtering skipped.")
                self.apriori_rule_antecedents = None
            else:
                print(f"Loaded Apriori rule from {self.rule_path}\n  Rule Antecedents: {self.apriori_rule_antecedents}")
                rule_ok = True
        except FileNotFoundError: print(f"INFO: Apriori rule file not found at '{self.rule_path}'. Filtering skipped."); self.apriori_rule_antecedents = None
        except Exception as e: print(f"ERROR loading Apriori rule '{self.rule_path}': {e}. Filtering skipped."); self.apriori_rule_antecedents = None

        # Set the overall loaded status based on essential components
        self.is_loaded = model_ok and preprocessor_ok
        # --- End Setting Status ---

        if self.is_loaded: print("Prediction artifacts (model & preprocessor) loaded successfully.")
        else: print("ERROR: Failed to load essential prediction artifacts. Predictions disabled.")


    def predict_traffic(self, features_df, threshold=DEFAULT_PREDICTION_THRESHOLD): # Use adjusted default
        """
        Predicts traffic using DNN and applies Apriori filtering if rule loaded.
        Assumes features_df contains the KDD_COLUMNS + metadata columns (_*).
        Returns predictions (0=Normal, 1=Attack) as a numpy array, or None on error.
        """
        if not self.is_loaded: return None
        if features_df.empty: return np.array([])

        # --- Apriori Data Prep ---
        apriori_sets = []
        if self.apriori_rule_antecedents is not None:
            apriori_match_data = pd.DataFrame()
            for col in DISCRETE_FEATURES_APRIORI:
                if col in features_df.columns:
                    apriori_match_data[col] = col + '=' + features_df[col].fillna('NA').astype(str)
            if not apriori_match_data.empty:
                apriori_sets = apriori_match_data.apply(lambda row: set(row.dropna()), axis=1).tolist()
            else: apriori_sets = [set() for _ in range(len(features_df))]

        # --- DNN Data Prep ---
        try: dnn_input_df = features_df[KDD_COLUMNS].copy()
        except KeyError as e: print(f"ERROR: Missing KDD column: {e}"); return None
        try: X_processed = self.preprocessor.transform(dnn_input_df)
        except Exception as e: print(f"ERROR during preprocessing: {e}"); return None

        # --- DNN Prediction ---
        try:
            dnn_predictions_prob = self.model.predict(X_processed, verbose=0)
            dnn_predictions = (dnn_predictions_prob > threshold).astype(int).flatten() # Apply threshold
        except Exception as e: print(f"ERROR during model prediction: {e}"); return None

        # --- Apriori Filtering ---
        final_predictions = dnn_predictions.copy()
        if self.apriori_rule_antecedents is not None and len(apriori_sets) == len(final_predictions):
            attack_indices = np.where(dnn_predictions == 1)[0]
            for idx in attack_indices:
                if self.apriori_rule_antecedents.issubset(apriori_sets[idx]):
                    final_predictions[idx] = 0 # Override to Normal

        return final_predictions