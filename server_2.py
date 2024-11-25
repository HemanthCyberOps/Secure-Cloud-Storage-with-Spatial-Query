from flask import Flask, request, jsonify
from paillier import public_key, private_key, EncryptedNumber

app = Flask(__name__)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Decrypt encrypted values."""
    try:
        encrypted_data = request.json.get('encrypted_data')

        if isinstance(encrypted_data, str):
            encrypted_number = EncryptedNumber(public_key, int(encrypted_data))
            decrypted_value = private_key.decrypt(encrypted_number)
            return jsonify({"decrypted_value": decrypted_value}), 200
        elif isinstance(encrypted_data, list):
            decrypted_values = [
                private_key.decrypt(EncryptedNumber(public_key, int(text)))
                for text in encrypted_data
            ]
            return jsonify({"decrypted_values": decrypted_values}), 200
        else:
            return jsonify({"error": "Invalid input. Provide a string or list of encrypted data."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(port=5002, debug=True)
