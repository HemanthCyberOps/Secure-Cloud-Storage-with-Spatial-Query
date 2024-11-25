import pandas as pd
from flask import Flask, request, jsonify
from paillier import encrypt_data, EncryptedNumber, homomorphic_addition, decrypt_data,public_key
from token_manager import TokenManager
import os
from azure.storage.blob import BlobServiceClient

app = Flask(__name__)

# Azure Blob Storage configuration
blob_service_client = BlobServiceClient.from_connection_string(os.getenv("AZURE_STORAGE_CONNECTION_STRING"))
blob_client = blob_service_client.get_blob_client(container="datasets", blob="modified_healthcare_dataset.csv")

# Use Redis-backed TokenManager
token_manager = TokenManager()

@app.route('/knn_query', methods=['POST'])
def knn_query():
    """Perform a KNN query using latitude and longitude."""
    query_token = request.headers.get("Query-Token")
    access_token = request.headers.get("Authorization")
    if not token_manager.validate_query_token(access_token, query_token):
        return jsonify({"error": "Unauthorized access"}), 401

    try:
        query = request.json
        query_lat = query.get("latitude")
        query_lon = query.get("longitude")
        k = query.get("k")

        if query_lat is None or query_lon is None or k is None:
            return jsonify({"error": "Missing required fields: 'latitude', 'longitude', or 'k'"}), 400
        if not isinstance(query_lat, (int, float)) or not isinstance(query_lon, (int, float)):
            return jsonify({"error": "'latitude' and 'longitude' must be numeric values."}), 400
        if not isinstance(k, int) or k <= 0:
            return jsonify({"error": "'k' must be a positive integer."}), 400

        downloaded_blob = blob_client.download_blob().content_as_text()
        data_store = pd.read_csv(pd.compat.StringIO(downloaded_blob))

        if data_store.empty:
            return jsonify({"error": "Dataset is empty. Please add data."}), 400

        data_store["distance"] = data_store.apply(
            lambda row: ((row["latitude"] - query_lat) ** 2 + (row["longitude"] - query_lon) ** 2) ** 0.5, axis=1
        )
        knn_results = data_store.nsmallest(k, "distance")[
            ["name", "age", "gender", "blood_type", "medical_condition",
             "doctor", "hospital", "insurance_provider", "distance"]
        ]
        return jsonify({"knn_results": knn_results.to_dict(orient="records")}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/generate_token', methods=['POST'])
def generate_token():
    """Generate an access token for users."""
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({"error": "Missing 'user_id'"}), 400
    token = token_manager.generate_access_token(user_id)
    return jsonify({"token": token}), 200


@app.route('/generate_query_token', methods=['POST'])
def generate_query_token():
    """Generate a query-specific token."""
    access_token = request.headers.get("Authorization")
    if not token_manager.validate_access_token(access_token):
        return jsonify({"error": "Unauthorized access"}), 401
    query_token = token_manager.generate_query_token(access_token)
    return jsonify({"query_token": query_token}), 200


@app.route('/view_encrypted', methods=['POST'])
def view_encrypted():
    """View encrypted data for a specific field and name."""
    try:
        downloaded_blob = blob_client.download_blob().content_as_text()
        data_store = pd.read_csv(pd.compat.StringIO(downloaded_blob))
        field = request.json.get("field")
        name = request.json.get("name")

        if not field or not name:
            return jsonify({"error": "Field and name must be provided."}), 400
        if field not in data_store.columns:
            return jsonify({"error": f"Field '{field}' not found in the dataset."}), 400

        # Filter dataset for the given name
        filtered_data = data_store[data_store['name'] == name]
        if filtered_data.empty:
            return jsonify({"error": f"No records found for name '{name}'."}), 404

        # Encrypt the selected field
        encrypted_values = encrypt_data(filtered_data[field].tolist())
        encrypted_result = [str(enc_value.ciphertext()) for enc_value in encrypted_values]

        return jsonify({"encrypted_data": encrypted_result}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/homomorphic_add_two_names', methods=['POST'])
def homomorphic_add_two_names():
    """Perform homomorphic addition of encrypted values from two names."""
    try:
        downloaded_blob = blob_client.download_blob().content_as_text()
        data_store = pd.read_csv(pd.compat.StringIO(downloaded_blob))
        field = request.json.get('field')
        name1 = request.json.get('name1')
        name2 = request.json.get('name2')

        if not field or not name1 or not name2:
            return jsonify({"error": "Field, name1, and name2 must be provided."}), 400
        if field not in data_store.columns:
            return jsonify({"error": f"Field '{field}' not found in the dataset."}), 400

        # Filter dataset for the given names
        data_name1 = data_store[data_store['name'] == name1]
        data_name2 = data_store[data_store['name'] == name2]

        if data_name1.empty:
            return jsonify({"error": f"No records found for name '{name1}'."}), 404
        if data_name2.empty:
            return jsonify({"error": f"No records found for name '{name2}'."}), 404

        # Ensure only one record per name is processed
        if len(data_name1) > 1 or len(data_name2) > 1:
            return jsonify({"error": "Multiple records found for one or both names. Please ensure unique names."}), 400

        # Encrypt the values for the field
        encrypted_value1 = encrypt_data(data_name1[field].tolist())[0]
        encrypted_value2 = encrypt_data(data_name2[field].tolist())[0]

        # Perform homomorphic addition
        encrypted_sum = encrypted_value1 + encrypted_value2

        return jsonify({
            "field": field,
            "name1": name1,
            "name2": name2,
            "encrypted_sum": str(encrypted_sum.ciphertext())
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Decrypt encrypted values."""
    try:
        encrypted_data = request.json.get('encrypted_data')
        if isinstance(encrypted_data, str):
            encrypted_number = EncryptedNumber(public_key, int(encrypted_data))
            decrypted_value = decrypt_data([encrypted_number])[0]
            return jsonify({"decrypted_value": decrypted_value}), 200
        elif isinstance(encrypted_data, list):
            encrypted_numbers = [EncryptedNumber(public_key, int(text)) for text in encrypted_data]
            decrypted_values = decrypt_data(encrypted_numbers)
            return jsonify({"decrypted_values": decrypted_values}), 200
        else:
            return jsonify({"error": "Invalid or missing 'encrypted_data'. Expected a string or a list."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5001)), debug=True)
