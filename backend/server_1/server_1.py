import pandas as pd
import os
import sys
from phe.util import invert
import numpy as np
# Add backend to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from flask import Flask, request, jsonify
from shared.paillier import encrypt_data, decrypt_data, homomorphic_addition, homomorphic_multiplication,public_key,EncryptedNumber,private_key
from shared.token_manager import TokenManager
from shared.BloomFilter import MultiLevelBloomFilter
import os
import requests

app = Flask(__name__)

# Load dataset
dataset_path = os.path.join("backend", "dataset", "reduced_healthcare_dataset.csv")
if not os.path.exists(dataset_path):
    raise FileNotFoundError(f"Dataset not found at path: {dataset_path}")

data_store = pd.read_csv(dataset_path)
data_store["billing_amount_encrypted"] = encrypt_data(data_store["billing_amount"].fillna(0).tolist())

# Initialize Token Manager & Bloom Filter
token_manager = TokenManager()
bloom_filter = MultiLevelBloomFilter()
for _, row in data_store.iterrows():
    bloom_filter.add("name", row["name"])

# Server 2 URL for decryption
SERVER_2_URL = "http://127.0.0.1:5002"

@app.before_request
def require_authorization():
    """Require valid tokens for all queries except token generation."""
    if request.endpoint not in ['generate_token', 'generate_query_token']:
        token = request.headers.get("Authorization")
        if not token or not token_manager.validate_access_token(token):
            return jsonify({"error": "Unauthorized access"}), 401

@app.route('/exact_match', methods=['POST'])
def exact_match():
    """Secure Exact Match Query using Bloom Filter."""
    access_token = request.headers.get("Authorization")
    query_token = request.headers.get("Query-Token")

    if not token_manager.validate_query_token(access_token, query_token):
        return jsonify({"error": "Unauthorized query"}), 401

    request_data = request.get_json()
    field, value = request_data.get('field'), request_data.get('value')

    if not field or not value:
        return jsonify({"error": "Field and value are required"}), 400

    value = str(value).strip().lower()

    if not bloom_filter.lookup(field, value):
        return jsonify({"error": f"No exact match found for {value}"}), 404

    # Drop NaN values in the field before filtering
    results = data_store.dropna(subset=[field])

    # Apply strict exact match filtering
    results = results[results[field].astype(str).str.lower().str.strip() == value]

    # Drop duplicates and NaN values in selected fields
    selected_fields = ["name", "medical_condition", "insurance_provider", "gender"]
    results = results[selected_fields].drop_duplicates().dropna()

    if results.empty:
        return jsonify({"message": f"No exact match found for {value}"}), 404

    return jsonify({"results": results.to_dict(orient="records")}), 200

@app.route('/range_query', methods=['POST'])
def range_query():
    access_token = request.headers.get("Authorization")
    query_token = request.headers.get("Query-Token")
    
    if not token_manager.validate_query_token(access_token, query_token):
        return jsonify({"error": "Unauthorized query"}), 401

    request_data = request.get_json()
    field, min_val, max_val = request_data.get('field'), request_data.get('min'), request_data.get('max')

    if not field or min_val is None or max_val is None:
        return jsonify({"error": "Field, min, and max values required"}), 400

    if not bloom_filter.lookup(field, str(min_val)) and not bloom_filter.lookup(field, str(max_val)):
        return jsonify({"error": "No values found in Bloom Filter for the given range"}), 404

    # Convert encrypted values to list before decryption
    encrypted_values = data_store["billing_amount_encrypted"].tolist()
    
    # Ensure decryption is applied correctly to each EncryptedNumber
    decrypted_values = np.array([decrypt_data(enc) for enc in encrypted_values])

    # Apply range filter
    mask = (decrypted_values >= min_val) & (decrypted_values <= max_val)
    results = data_store[mask]

    # Select only required fields and remove duplicates
    selected_fields = ["name", "medical_condition", "insurance_provider", "gender"]
    results = results[selected_fields].drop_duplicates().dropna()

    return jsonify({"results": results.to_dict(orient="records")}), 200
@app.route('/knn_query', methods=['POST'])
def knn_query():
    access_token = request.headers.get("Authorization")
    query_token = request.headers.get("Query-Token")
    
    if not token_manager.validate_query_token(access_token, query_token):
        return jsonify({"error": "Unauthorized query"}), 401

    request_data = request.get_json()
    latitude, longitude, k = request_data.get('latitude'), request_data.get('longitude'), request_data.get('k', 5)

    data_store["distance"] = ((data_store["latitude"] - latitude) ** 2 + (data_store["longitude"] - longitude) ** 2) ** 0.5
    results = data_store.nsmallest(k, "distance")
    selected_fields = ["name", "medical_condition", "insurance_provider", "gender"]
    results = results[selected_fields].drop_duplicates().dropna()
    
    return jsonify({"results": results.to_dict(orient="records")}), 200

@app.route('/get_encrypted_billing', methods=['POST'])
def get_encrypted_billing():
    """Retrieve encrypted billing amount for a specific user."""
    access_token = request.headers.get("Authorization")
    if not token_manager.validate_access_token(access_token):
        return jsonify({"error": "Unauthorized"}), 401

    request_data = request.get_json()
    user_names = request_data.get("names")
    if not user_names or not isinstance(user_names, list):
        return jsonify({"error": "Provide a list of names"}), 400

    user_names = [str(name).strip().lower() for name in user_names]
    user_data = data_store[data_store["name"].astype(str).str.lower().str.strip().isin(user_names)]

    if user_data.empty:
        return jsonify({"error": "No data found for the given names"}), 404

    encrypted_values = user_data["billing_amount_encrypted"].tolist()
    encrypted_values = [str(enc.ciphertext()) for enc in encrypted_values]

    return jsonify({"names": user_names, "billing_amounts_encrypted": encrypted_values}), 200

@app.route('/homomorphic_sum', methods=['POST'])
def homomorphic_sum():
    """Perform Homomorphic Summation with Modular Reduction."""
    try:
        data = request.json
        names = data.get("names")

        if not names or not isinstance(names, list):
            return jsonify({"error": "Provide a list of names"}), 400

        encrypted_values = []
        for name in names:
            records = data_store[data_store["name"] == name]
            if records.empty:
                return jsonify({"error": f"No records found for {name}"}), 404
            encrypted_values.extend(records["billing_amount_encrypted"].tolist())

        if not encrypted_values:
            return jsonify({"error": "No encrypted values found"}), 400

        encrypted_sum = homomorphic_addition(*encrypted_values)
        n_squared = public_key.n ** 2  

        # Ensure encrypted sum does not exceed limits
        encrypted_sum_value = encrypted_sum.ciphertext() % n_squared

        # Properly reconstruct EncryptedNumber
        encrypted_sum = EncryptedNumber(public_key, encrypted_sum_value, exponent=0)

        return jsonify({"encrypted_sum": str(encrypted_sum.ciphertext())}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/decrypt_sum', methods=['POST'])
def decrypt_sum():
    """Forward encrypted sum to Server 2 for decryption."""
    try:
        data = request.json
        encrypted_sum = data.get("encrypted_sum")

        if not encrypted_sum:
            return jsonify({"error": "Missing encrypted_sum"}), 400

        response = requests.post(f"{SERVER_2_URL}/decrypt_sum", json={"encrypted_sum": encrypted_sum})

        return jsonify(response.json()), response.status_code

    except Exception as e:
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(port=5001, debug=True)
