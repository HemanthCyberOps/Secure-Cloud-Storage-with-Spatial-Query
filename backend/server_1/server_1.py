import pandas as pd
from flask import Flask, request, jsonify
from shared.paillier import encrypt_data, decrypt_data, homomorphic_addition, homomorphic_multiplication
from shared.token_manager import TokenManager
from shared.BloomFilter import MultiLevelBloomFilter
import os
import requests

app = Flask(__name__)

# Load dataset
dataset_path = "reduced_healthcare_dataset.csv"
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
def exact_match_query():
    """Secure Exact Match Query using Bloom Filter."""
    access_token = request.headers.get("Authorization")
    query_token = request.headers.get("Query-Token")
    if not token_manager.validate_query_token(access_token, query_token):
        return jsonify({"error": "Unauthorized query"}), 401

    request_data = request.get_json()
    field, value = request_data.get('field'), request_data.get('value')

    if not field or value is None:
        return jsonify({"error": "Field and value required"}), 400

    if not bloom_filter.lookup(field, value):
        return jsonify({"error": f"Value {value} not found"}), 404

    results = data_store[data_store[field] == value].to_dict(orient="records")
    return jsonify({"results": results}), 200

@app.route('/range_query', methods=['POST'])
def range_query():
    """Perform Secure Range Query on encrypted data."""
    access_token = request.headers.get("Authorization")
    query_token = request.headers.get("Query-Token")
    if not token_manager.validate_query_token(access_token, query_token):
        return jsonify({"error": "Unauthorized query"}), 401

    request_data = request.get_json()
    field, min_val, max_val = request_data.get('field'), request_data.get('min'), request_data.get('max')

    if not field or min_val is None or max_val is None:
        return jsonify({"error": "Field, min, and max values required"}), 400

    # Bloom Filter Lookup Optimization
    if not bloom_filter.lookup(field, str(min_val)) and not bloom_filter.lookup(field, str(max_val)):
        return jsonify({"error": "No values found in Bloom Filter for the given range"}), 404

    encrypted_values = data_store["billing_amount_encrypted"]
    if encrypted_values.empty:
        return jsonify({"error": "No encrypted values found"}), 400

    decrypted_values = decrypt_data(encrypted_values)

    mask = (decrypted_values >= min_val) & (decrypted_values <= max_val)
    results = data_store[mask].to_dict(orient="records")

    if not results:
        return jsonify({"message": "No records found in the given range"}), 404

    return jsonify({"results": results}), 200

@app.route('/knn_query', methods=['POST'])
def knn_query():
    """Perform Secure K-Nearest Neighbors Query."""
    access_token = request.headers.get("Authorization")
    query_token = request.headers.get("Query-Token")
    if not token_manager.validate_query_token(access_token, query_token):
        return jsonify({"error": "Unauthorized query"}), 401

    request_data = request.get_json()
    latitude, longitude, k = request_data.get('latitude'), request_data.get('longitude'), request_data.get('k', 5)

    if latitude is None or longitude is None:
        return jsonify({"error": "Latitude and longitude required"}), 400

    data_store["distance"] = ((data_store["latitude"] - latitude) ** 2 + (data_store["longitude"] - longitude) ** 2) ** 0.5
    results = data_store.nsmallest(k, "distance").to_dict(orient="records")

    return jsonify({"results": results}), 200

@app.route('/homomorphic_sum', methods=['POST'])
def homomorphic_sum():
    """Perform Homomorphic Summation on Encrypted Data."""
    access_token = request.headers.get("Authorization")
    query_token = request.headers.get("Query-Token")
    if not token_manager.validate_query_token(access_token, query_token):
        return jsonify({"error": "Unauthorized query"}), 401

    encrypted_values = data_store["billing_amount_encrypted"]
    encrypted_sum = sum(encrypted_values)

    return jsonify({"encrypted_sum": str(encrypted_sum)}), 200

@app.route('/decrypt_sum', methods=['POST'])
def forward_decryption_to_server_2():
    """Forward encrypted sum to Server 2 for decryption."""
    encrypted_sum = request.json.get('encrypted_sum')

    try:
        response = requests.post(f"{SERVER_2_URL}/decrypt", json={"encrypted_data": [encrypted_sum]})
        return response.json(), 200
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Server 2 is not reachable"}), 503

if __name__ == "__main__":
    app.run(port=5001, debug=True)
