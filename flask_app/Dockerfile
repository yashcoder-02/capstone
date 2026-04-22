FROM python:3.10-slim

WORKDIR /app

# FIX #2 — install Docker CLI so Flask container can also call `docker exec` on vol containers
RUN apt-get update && apt-get install -y \
    docker.io \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# FIX #3 — requirements.txt now has actual packages
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/db /app/dumps /app/reports

EXPOSE 5000

CMD ["python", "app.py"]
