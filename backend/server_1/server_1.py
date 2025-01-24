import pandas as pd
from flask import Flask, request, jsonify
from backend.shared.paillier import public_key, encrypt_data, decrypt_data, homomorphic_addition, homomorphic_multiplication
from backend.shared.token_manager import TokenManager
from backend.shared.BloomFilter import BloomFilter
import os
import requests

app = Flask(__name__)

# Dataset path
dataset_path = "reduced_healthcare_dataset.csv"

# Load dataset
if not os.path.exists(dataset_path):
    raise FileNotFoundError(f"Dataset not found at path: {dataset_path}")

data_store = pd.read_csv(dataset_path)
print(f"Dataset loaded successfully. Records: {len(data_store)}")

# Ensure billing_amount column has no NaN values
if "billing_amount" in data_store.columns:
    data_store["billing_amount"] = data_store["billing_amount"].fillna(0)
    data_store["billing_amount"] = pd.to_numeric(data_store["billing_amount"], errors='coerce').fillna(0)
    data_store["billing_amount_encrypted"] = encrypt_data(data_store["billing_amount"].tolist())
else:
    print("[ERROR] 'billing_amount' column is missing from the dataset.")

# Initialize Redis Token Manager
token_manager = TokenManager()

# Initialize Bloom Filter
bloom_filter = BloomFilter()

# Add existing records to Bloom Filter
for index, row in data_store.iterrows():
    bloom_filter.add("name", row["name"])

# Server 2 URL for decryption
SERVER_2_URL = "http://127.0.0.1:5002"

# ✅ **Function: Require Authorization for API Access**
@app.before_request
def require_authorization():
    """Require valid access tokens for all endpoints except token generation."""
    if request.endpoint not in ['generate_token', 'generate_query_token']:
        token = request.headers.get("Authorization")
        if not token or not token_manager.validate_access_token(token):
            return jsonify({"error": "Unauthorized access. Invalid token."}), 401

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "running"}), 200


@app.route('/generate_query_token', methods=['POST'])
def generate_query_token():
    """Generate a query-specific token for secure data queries."""
    access_token = request.headers.get("Authorization")
    if not token_manager.validate_access_token(access_token):
        return jsonify({"error": "Unauthorized access"}), 401
    query_token = token_manager.generate_query_token(access_token)
    return jsonify({"query_token": query_token}), 200

# ✅ **API: Exact Match Query (Secure)**
@app.route('/exact_match', methods=['POST'])
def exact_match_query():
    """Handle exact match queries with token validation and Bloom Filter."""
    query_token = request.headers.get("Query-Token")
    access_token = request.headers.get("Authorization")

    if not query_token or not token_manager.validate_query_token(access_token, query_token):
        return jsonify({"error": "Unauthorized access. Invalid or missing query token."}), 401

    try:
        request_data = request.get_json()
        field = request_data.get('field')
        value = request_data.get('value')

        if not field or value is None:
            return jsonify({"error": "Field and value must be provided."}), 400

        if not bloom_filter.lookup(field, value):
            return jsonify({"error": f"Value not found in dataset for {field} = {value}."}), 404

        matched_data = data_store[data_store[field] == value]
        if matched_data.empty:
            return jsonify({"error": f"No records found for {field} = {value}."}), 404

        results = matched_data[["name", "hospital", "medical_condition", "insurance_provider"]].to_dict(orient="records")
        return jsonify({"results": results}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ✅ **API: Range Query (Secure)**
@app.route('/range_query', methods=['POST'])
def range_query():
    """Handle range queries with token validation."""
    query_token = request.headers.get("Query-Token")
    access_token = request.headers.get("Authorization")

    if not query_token or not token_manager.validate_query_token(access_token, query_token):
        return jsonify({"error": "Unauthorized access. Invalid or missing query token."}), 401

    try:
        request_data = request.get_json()
        field = request_data.get('field')
        min_value = request_data.get('min_value')
        max_value = request_data.get('max_value')

        if not field or min_value is None or max_value is None:
            return jsonify({"error": "Field, min_value, and max_value must be provided."}), 400

        if field not in data_store.columns or data_store[field].dtype not in ['int64', 'float64']:
            return jsonify({"error": f"Field '{field}' must be numeric for range queries."}), 400

        range_data = data_store[(data_store[field] >= min_value) & (data_store[field] <= max_value)]
        results = range_data[["name", "hospital", "medical_condition", "insurance_provider"]].to_dict(orient="records")

        return jsonify({"results": results}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ✅ **API: KNN Query**
@app.route('/knn_query', methods=['POST'])
def knn_query():
    """Perform a KNN query using latitude and longitude."""
    query_token = request.headers.get("Query-Token")
    access_token = request.headers.get("Authorization")

    if not query_token or not token_manager.validate_query_token(access_token, query_token):
        return jsonify({"error": "Unauthorized access. Invalid or missing query token."}), 401

    try:
        request_data = request.get_json()
        query_lat = request_data.get("latitude")
        query_lon = request_data.get("longitude")
        k = request_data.get("k")

        if query_lat is None or query_lon is None or k is None:
            return jsonify({"error": "Latitude, longitude, and k must be provided."}), 400

        data_store["distance"] = ((data_store["latitude"] - query_lat) ** 2 + (data_store["longitude"] - query_lon) ** 2) ** 0.5
        knn_results = data_store.nsmallest(k, "distance")[["name", "hospital", "medical_condition", "insurance_provider", "distance"]]
        return jsonify({"knn_results": knn_results.to_dict(orient="records")}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ✅ **API: Homomorphic Sum Decryption (Forward to Server 2)**
@app.route('/decrypt_sum', methods=['POST'])
def forward_decryption_to_server_2():
    """Forward the decryption request to Server 2."""
    try:
        encrypted_sum = request.json.get('encrypted_sum')
        response = requests.post(f"{SERVER_2_URL}/decrypt", json={"encrypted_data": [encrypted_sum]})
        return response.json(), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(port=5001, debug=True)
