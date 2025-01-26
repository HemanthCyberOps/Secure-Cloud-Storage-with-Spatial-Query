FROM python:3.9

WORKDIR /app

# Copy the entire backend folder (including shared utilities)
COPY ../../backend /app

# Set the working directory to server_0
WORKDIR /app/server_0

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000
CMD ["python", "server_0.py"]
