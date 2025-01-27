# Use Python 3.9 as the base image
FROM python:3.9

# Set the working directory inside the container
WORKDIR /app

# Copy only the necessary files from server_0
COPY . /app

# Upgrade pip to avoid issues
RUN pip install --no-cache-dir --upgrade pip

# Install dependencies from requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Expose the Flask server port
EXPOSE 5000

# Set environment variables for Azure (avoid putting passwords here)
ENV REDIS_HOST="securestorage-redis.redis.cache.windows.net"
ENV REDIS_PORT="6379"

# Run the Flask server
CMD ["python", "/app/server_0.py"]
