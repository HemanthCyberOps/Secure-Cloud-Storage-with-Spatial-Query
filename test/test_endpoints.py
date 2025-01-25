import requests

BASE_URL_SERVER_0 = "http://127.0.0.1:5000"
BASE_URL_SERVER_1 = "http://127.0.0.1:5001"
BASE_URL_SERVER_2 = "http://127.0.0.1:5002"

# Test Token Generation
def test_generate_token():
    payload = {"username": "testuser", "password": "testpassword"}
    response = requests.post(f"{http://127.0.0.1:5000}/generate_token", json=payload)
    assert response.status_code == 200
    assert "access_token" in response.json()

# Test Query Token Generation
def test_generate_query_token():
    access_token = "test_access_token"  # Replace with a valid token if needed
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.post(f"{http://127.0.0.1:5000}/generate_query_token", headers=headers)
    assert response.status_code == 200
    assert "query_token" in response.json()

# Test Exact Match Query
def test_exact_match_query():
    access_token = "test_access_token"
    query_token = "test_query_token"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Query-Token": query_token
    }
    payload = {"field": "name", "value": "John Doe"}
    response = requests.post(f"{http://127.0.0.1:5001}/exact_match", headers=headers, json=payload)
    assert response.status_code == 200 or response.status_code == 404  # Either success or not found

# Test Range Query
def test_range_query():
    access_token = "test_access_token"
    query_token = "test_query_token"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Query-Token": query_token
    }
    payload = {"field": "billing_amount", "min": 100, "max": 500}
    response = requests.post(f"{http://127.0.0.1:5001}/range_query", headers=headers, json=payload)
    assert response.status_code == 200
    assert "results" in response.json()

# Test Homomorphic Sum
def test_homomorphic_sum():
    access_token = "test_access_token"
    query_token = "test_query_token"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Query-Token": query_token
    }
    response = requests.post(f"{http://127.0.0.1:5001}/homomorphic_sum", headers=headers)
    assert response.status_code == 200
    assert "encrypted_sum" in response.json()

# Test Decryption by Server 2
def test_decrypt_sum():
    encrypted_sum = "test_encrypted_sum"  # Replace with valid encrypted data
    payload = {"encrypted_sum": encrypted_sum}
    response = requests.post(f"{http://127.0.0.1:5002}/decrypt", json=payload)
    assert response.status_code == 200
    assert "decrypted_result" in response.json()

