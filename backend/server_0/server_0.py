import pandas as pd
import os
import pickle
from flask import Flask, jsonify, request
from shared.BloomFilter import BloomFilter
from shared.token_manager import TokenManager

app = Flask(__name__)
token_manager = TokenManager()

# File Paths
dataset_path = "reduced_healthcare_dataset.csv"
bloom_filter_path = "bloom_filter.pkl"

# Load dataset
if os.path.exists(dataset_path):
    data_store = pd.read_csv(dataset_path)
    print("Dataset loaded successfully.")
else:
    print(f"Dataset not found at {dataset_path}. Initializing with an empty DataFrame.")
    data_store = pd.DataFrame(columns=[
        "name", "age", "gender", "blood_type", "medical_condition",
        "date_of_admission", "doctor", "hospital", "insurance_provider",
        "billing_amount", "room_number", "admission_type",
        "discharge_date", "medication", "test_results", "latitude", "longitude"
    ])

# Load or initialize Bloom Filter
if os.path.exists(bloom_filter_path):
    with open(bloom_filter_path, "rb") as f:
        bloom_filter = pickle.load(f)
else:
    bloom_filter = BloomFilter()

# Add existing dataset records to Bloom Filter
for index, row in data_store.iterrows():
    bloom_filter.add("name", row["name"])

# Save Bloom Filter persistently
def save_bloom_filter():
    with open(bloom_filter_path, "wb") as f:
        pickle.dump(bloom_filter, f)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "running"}), 200

@app.route('/generate_token', methods=['POST'])
def generate_token():
    """Generate an access token for users."""
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({"error": "Missing 'user_id'"}), 400
    token = token_manager.generate_access_token(user_id)
    return jsonify({"token": token}), 200

@app.route('/add_data', methods=['POST'])
def add_data():
    """Add new patient data to the dataset and update Bloom Filter persistently."""
    token = request.headers.get("Authorization")
    if not token or not token_manager.validate_access_token(token):
        return jsonify({"error": "Unauthorized access"}), 401

    new_data = request.json
    if not new_data:
        return jsonify({"error": "Invalid or missing data"}), 400

    try:
        bloom_filter.add("name", new_data["name"])
        save_bloom_filter()

        global data_store
        new_row = pd.DataFrame([new_data])
        data_store = pd.concat([data_store, new_row], ignore_index=True)
        data_store.to_csv(dataset_path, index=False)

        return jsonify({"status": "Data added successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/view_data', methods=['GET'])
def view_data():
    """Retrieve stored patient data (Only Authorized Users)."""
    token = request.headers.get("Authorization")
    if not token or not token_manager.validate_access_token(token):
        return jsonify({"error": "Unauthorized access"}), 401

    return jsonify(data_store.to_dict(orient="records")), 200

if __name__ == "__main__":
    app.run(port=5000, debug=True)
