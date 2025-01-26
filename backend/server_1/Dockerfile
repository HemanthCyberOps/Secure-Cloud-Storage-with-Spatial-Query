FROM python:3.9

WORKDIR /app

# Copy the entire backend folder (including shared utilities)
COPY ../../backend /app

# Set the working directory to server_0
WORKDIR /app/server_1

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5001
CMD ["python", "server_1.py"]
