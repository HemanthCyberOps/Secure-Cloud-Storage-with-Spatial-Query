import pandas as pd
from flask import Flask, jsonify, request
from BloomFilter import BloomFilter
from token_manager import TokenManager
import os
from azure.storage.blob import BlobServiceClient

app = Flask(__name__)

# Azure Blob Storage configuration
blob_service_client = BlobServiceClient.from_connection_string(os.getenv("AZURE_STORAGE_CONNECTION_STRING"))
blob_client = blob_service_client.get_blob_client(container="datasets", blob="modified_healthcare_dataset.csv")

# Load dataset from Azure Blob Storage
try:
    downloaded_blob = blob_client.download_blob().content_as_text()
    data_store = pd.read_csv(pd.compat.StringIO(downloaded_blob))
    print("Dataset loaded successfully.")
except Exception as e:
    print(f"Error loading dataset: {e}")
    data_store = pd.DataFrame(columns=[
        "name", "age", "gender", "blood_type", "medical_condition",
        "date_of_admission", "doctor", "hospital", "insurance_provider",
        "billing_amount", "room_number", "admission_type",
        "discharge_date", "medication", "test_results", "latitude", "longitude"
    ])

# Use Redis-backed TokenManager
token_manager = TokenManager()

# Initialize Bloom Filter
bloom_filter = BloomFilter()
for index, row in data_store.iterrows():
    bloom_filter.add("Name", row["name"])


def save_dataset_to_blob():
    """Save the updated dataset to Azure Blob Storage."""
    global data_store
    try:
        blob_client.upload_blob(data_store.to_csv(index=False), overwrite=True)
        print("Dataset saved to Azure Blob Storage.")
    except Exception as e:
        print(f"Error saving dataset: {e}")


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
        bloom_filter.add("Name", new_data["name"])
        global data_store
        new_row = pd.DataFrame([new_data])
        data_store = pd.concat([data_store, new_row], ignore_index=True)
        save_dataset_to_blob()
        return jsonify({"status": "Data added successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/view_data', methods=['GET'])
def view_data():
    """View the data from the dataset with optional filtering."""
    try:
        field = request.args.get("field")
        value = request.args.get("value")
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 10))

        filtered_data = data_store
        if field and value:
            if field not in data_store.columns:
                return jsonify({"error": f"Field '{field}' not found in the dataset."}), 400
            filtered_data = data_store[data_store[field] == value]

        total = len(filtered_data)
        paginated_data = filtered_data.iloc[(page - 1) * per_page: page * per_page]
        return jsonify({
            "data": paginated_data.to_dict(orient="records"),
            "page": page,
            "per_page": per_page,
            "total": total
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
