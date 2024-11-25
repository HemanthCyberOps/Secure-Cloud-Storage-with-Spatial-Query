import redis
import secrets
import os

class TokenManager:
    def __init__(self):
        # Retrieve Redis connection details from environment variables
        redis_host = os.getenv("AZURE_REDIS_HOST", "localhost")  # Default to localhost if not set
        redis_port = int(os.getenv("AZURE_REDIS_PORT", 6379))    # Default to 6379 if not set
        redis_password = os.getenv("AZURE_REDIS_PASSWORD", "")   # Default to an empty password

        # Validate Redis credentials
        if not redis_host or not redis_password:
            raise ValueError("Redis host or password is not set in environment variables!")

        # Connect to Azure Redis Cache
        try:
            self.redis_client = redis.StrictRedis(
                host=redis_host,
                port=redis_port,
                password=redis_password,
                decode_responses=True
            )
            # Test the connection
            self.redis_client.ping()
            print("Connected to Redis successfully.")
        except redis.ConnectionError as e:
            print(f"Failed to connect to Redis: {e}")
            raise

    def generate_access_token(self, user_id):
        """Generate and store a secure access token for a user."""
        if not user_id:
            raise ValueError("User ID is required to generate an access token.")
        token = secrets.token_hex(16)
        try:
            self.redis_client.set(token, user_id, ex=3600)  # Token expires in 1 hour
            return token
        except Exception as e:
            print(f"Error generating access token: {e}")
            raise

    def validate_access_token(self, token):
        """Validate if an access token exists in the Redis store."""
        try:
            return self.redis_client.exists(token)
        except Exception as e:
            print(f"Error validating access token: {e}")
            raise

    def generate_query_token(self, access_token):
        """Generate a query token for an authorized access token."""
        if not self.validate_access_token(access_token):
            raise ValueError("Invalid access token")
        query_token = secrets.token_hex(16)
        try:
            self.redis_client.set(query_token, access_token, ex=3600)  # Token expires in 1 hour
            return query_token
        except Exception as e:
            print(f"Error generating query token: {e}")
            raise

    def validate_query_token(self, access_token, query_token):
        """Validate if a query token is associated with the provided access token."""
        try:
            stored_access_token = self.redis_client.get(query_token)
            return stored_access_token == access_token
        except Exception as e:
            print(f"Error validating query token: {e}")
            raise
