import redis
import secrets
import os

class TokenManager:
    def __init__(self):
        """Initialize Redis connection for token management using environment variables."""
        self.redis_client = redis.StrictRedis(
            host=os.getenv("REDIS_HOST", "127.0.0.1"),  # Default to local Redis
            port=int(os.getenv("REDIS_PORT", "6379")),
            db=0,
            decode_responses=True
        )

    def generate_access_token(self, user_id):
        """Generate and store an access token for user authentication."""
        token = secrets.token_hex(32)  # 32-byte token for better security
        self.redis_client.set(token, user_id, ex=3600)  # Token expires in 1 hour
        return token

    def validate_access_token(self, token):
        """Check if an access token exists in Redis."""
        return self.redis_client.exists(token) == 1

    def revoke_tokens_for_user(self, user_id):
        """Revoke all tokens for a specific user."""
        keys = self.redis_client.keys("*")  # Fetch all stored keys
        for key in keys:
            if self.redis_client.get(key) == user_id:
                self.redis_client.delete(key)

    def generate_query_token(self, access_token, query):
        """Generate a query token linked to an access token and query."""
        if not self.validate_access_token(access_token):
            raise ValueError("Invalid access token")

        query_token = secrets.token_hex(32)
        self.redis_client.set(query_token, access_token, ex=600)  # Query token expires in 10 minutes
        return query_token

    def validate_query_token(self, access_token, query_token):
        """Validate if a query token is linked to the provided access token."""
        stored_access_token = self.redis_client.get(query_token)
        return stored_access_token == access_token

    def revoke_query_token(self, query_token):
        """Manually revoke a query token."""
        self.redis_client.delete(query_token)
