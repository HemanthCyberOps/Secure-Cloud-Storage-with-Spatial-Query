from flask import Flask, request, jsonify
from shared.paillier import public_key, private_key, EncryptedNumber

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health_check():
    """Check if Server 2 is running."""
    return jsonify({"status": "running"}), 200

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Decrypt data forwarded from Server 1."""
    try:
        encrypted_data = request.json.get('encrypted_data')

        if not encrypted_data or not isinstance(encrypted_data, list):
            return jsonify({"error": "Invalid or missing 'encrypted_data'. Expected a list."}), 400

        decrypted_values = []
        for ciphertext in encrypted_data:
            try:
                decrypted_value = private_key.decrypt(EncryptedNumber(public_key, int(ciphertext)))
                decrypted_values.append(decrypted_value)
            except Exception as e:
                print(f"[ERROR] Failed to decrypt value {ciphertext}: {e}")
                return jsonify({"error": f"Failed to decrypt value: {e}"}), 500

        return jsonify({"decrypted_values": decrypted_values}), 200

    except Exception as e:
        print(f"[ERROR] Decryption error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/decrypt_sum', methods=['POST'])
def decrypt_sum():
    """Decrypt sum of encrypted values received from Server 1."""
    try:
        encrypted_sum = request.json.get('encrypted_sum')

        if not encrypted_sum:
            return jsonify({"error": "Missing 'encrypted_sum'."}), 400

        decrypted_sum = private_key.decrypt(EncryptedNumber(public_key, int(encrypted_sum)))
        return jsonify({"decrypted_sum": decrypted_sum}), 200

    except Exception as e:
        print(f"[ERROR] Sum decryption error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/homomorphic_operations', methods=['POST'])
def homomorphic_operations():
    """Perform homomorphic addition and scalar multiplication."""
    try:
        request_data = request.json
        operation = request_data.get("operation")
        encrypted_values = request_data.get("encrypted_values")
        scalar = request_data.get("scalar")

        if not encrypted_values or not isinstance(encrypted_values, list):
            return jsonify({"error": "Invalid or missing 'encrypted_values'. Expected a list."}), 400

        enc_numbers = []
        for val in encrypted_values:
            try:
                enc_num = EncryptedNumber(public_key, int(val))
                enc_numbers.append(enc_num)
            except Exception as e:
                print(f"[ERROR] Invalid encrypted value {val}: {e}")
                return jsonify({"error": f"Invalid encrypted value: {e}"}), 400

        if operation == "addition":
            result_enc = sum(enc_numbers)
        elif operation == "multiplication":
            if scalar is None:
                return jsonify({"error": "Missing 'scalar' for multiplication."}), 400
            result_enc = enc_numbers[0] * scalar
        else:
            return jsonify({"error": "Invalid operation. Supported: 'addition', 'multiplication' with scalar."}), 400

        decrypted_result = private_key.decrypt(result_enc)
        return jsonify({"decrypted_result": decrypted_result}), 200

    except Exception as e:
        print(f"[ERROR] Homomorphic operation error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("[INFO] Server 2 is running on port 5002...")
    app.run(port=5002, debug=True)
