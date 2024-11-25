import redis
import secrets
import os

class TokenManager:
    def __init__(self):
        # Connect to Azure Redis Cache
        self.redis_client = redis.StrictRedis(
            host=os.getenv("AZURE_REDIS_HOST"),
            port=int(os.getenv("AZURE_REDIS_PORT")),
            password=os.getenv("AZURE_REDIS_PASSWORD"),
            decode_responses=True
        )

    def generate_access_token(self, user_id):
        """Generate and store a secure access token for a user."""
        token = secrets.token_hex(16)
        self.redis_client.set(token, user_id, ex=3600)  # Token expires in 1 hour
        return token

    def validate_access_token(self, token):
        """Validate if an access token exists in the Redis store."""
        return self.redis_client.exists(token)

    def generate_query_token(self, access_token):
        """Generate a query token for an authorized access token."""
        if not self.validate_access_token(access_token):
            raise ValueError("Invalid access token")
        query_token = secrets.token_hex(16)
        self.redis_client.set(query_token, access_token, ex=3600)  # Token expires in 1 hour
        return query_token

    def validate_query_token(self, access_token, query_token):
        """Validate if a query token is associated with the provided access token."""
        stored_access_token = self.redis_client.get(query_token)
        return stored_access_token == access_token
