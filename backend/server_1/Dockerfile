# Use Python 3.9 as the base image
FROM python:3.9

# Set the working directory inside the container
WORKDIR /app

# Copy only necessary files (ensure `requirements.txt` is included)
COPY requirements.txt /app/requirements.txt
COPY . /app

# Upgrade pip to avoid issues
RUN pip install --no-cache-dir --upgrade pip

# Install dependencies from requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Expose the Flask server port
EXPOSE 5001

# Run the Flask server
CMD ["python", "/app/server_1.py"]
