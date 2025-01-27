import os
import logging
import sys
import numpy as np
# Add the backend directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pandas as pd
import pickle
from shared.BloomFilter import BloomFilter
from shared.token_manager import TokenManager
from flask import Flask, jsonify, request

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
token_manager = TokenManager()

# Corrected paths for Azure App Service
DATASET_PATH = "/home/site/wwwroot/backend/dataset/reduced_healthcare_dataset.csv"
BLOOM_FILTER_PATH = "/home/site/wwwroot/bloom_filter.pkl"


data_store = None

# Load dataset
if os.path.exists(DATASET_PATH):
    try:
        data_store = pd.read_csv(DATASET_PATH)
        logging.info("Dataset loaded successfully.")
    except Exception as e:
        logging.error(f"Error loading dataset: {e}")
        data_store = pd.DataFrame()
else:
    logging.warning(f"Dataset not found at {DATASET_PATH}. Initializing an empty DataFrame.")
    data_store = pd.DataFrame(columns=[
        "name", "age", "gender", "blood_type", "medical_condition",
        "date_of_admission", "doctor", "hospital", "insurance_provider",
        "billing_amount", "room_number", "admission_type",
        "discharge_date", "medication", "test_results", "latitude", "longitude"
    ])

bloom_filter_path = "bloom_filter.pkl"

def save_bloom_filter():
    """Save the Bloom filter in a safe format."""
    try:
        with open(bloom_filter_path, "wb") as f:
            pickle.dump({
                "dimensions": bloom_filter.dimensions,
                "bit_array": bloom_filter.bit_array.tolist(),  # Convert NumPy array to list
                "num_hashes": bloom_filter.num_hashes
            }, f)
        print("Bloom filter saved successfully.")
    except Exception as e:
        print(f"Error saving Bloom filter: {e}")

if os.path.exists(bloom_filter_path):
    try:
        with open(bloom_filter_path, "rb") as f:
            bloom_data = pickle.load(f)
            bloom_filter = BloomFilter(dimensions=bloom_data["dimensions"], num_hashes=bloom_data["num_hashes"])
            bloom_filter.bit_array = np.array(bloom_data["bit_array"], dtype=bool)  # Convert list back to NumPy array
        print("Bloom filter loaded successfully.")
    except (EOFError, pickle.UnpicklingError, KeyError, TypeError) as e:
        print(f"Bloom filter file is corrupted: {e}. Initializing a new one.")
        bloom_filter = BloomFilter()
        save_bloom_filter()  # Force save a new one
else:
    print("No Bloom filter file found. Initializing a new one.")
    bloom_filter = BloomFilter()
    save_bloom_filter()  # Save the new Bloom filter

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "running"}), 200

@app.route('/generate_token', methods=['POST'])
def generate_token():
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({"error": "Missing 'user_id'"}), 400
    token = token_manager.generate_access_token(user_id)
    return jsonify({"token": token}), 200

@app.route('/generate_query_token', methods=['POST'])
def generate_query_token():
    access_token = request.headers.get("Authorization")
    if not access_token or not token_manager.validate_access_token(access_token):
        return jsonify({"error": "Unauthorized access"}), 401
    request_data = request.get_json()
    query = request_data.get("query")
    if not query:
        return jsonify({"error": "Query is required"}), 400
    query_token = token_manager.generate_query_token(access_token, query)
    return jsonify({"query_token": query_token}), 200

@app.route('/add_data', methods=['POST'])
def add_data():
    """Add data to the dataset and update the Bloom Filter."""
    token = request.headers.get("Authorization")
    if not token or not token_manager.validate_access_token(token):
        return jsonify({"error": "Unauthorized access"}), 401

    new_data = request.json
    if not new_data:
        return jsonify({"error": "Invalid or missing data"}), 400

    try:
        if "name" not in new_data:
            return jsonify({"error": "Missing required field: 'name'"}), 400

        bloom_filter.add("name", new_data["name"])  # Add to Bloom Filter
        save_bloom_filter()  # Persist the Bloom filter

        global data_store
        new_row = pd.DataFrame([new_data])
        data_store = pd.concat([data_store, new_row], ignore_index=True)
        data_store.to_csv(DATASET_PATH, index=False)

        return jsonify({"status": "Data added successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/view_data', methods=['GET'])
def view_data():
    token = request.headers.get("Authorization")
    if not token or not token_manager.validate_access_token(token):
        return jsonify({"error": "Unauthorized access"}), 401
    return jsonify(data_store.to_dict(orient="records")), 200

app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)

