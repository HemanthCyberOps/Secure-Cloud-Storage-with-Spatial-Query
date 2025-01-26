FROM python:3.9

WORKDIR /app
COPY . /app

# Copy shared folder
COPY ../shared /app/shared

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5001
CMD ["python", "server_1.py"]
