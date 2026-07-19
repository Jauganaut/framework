FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    docker.io \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Install cloudflared
RUN curl -L --output /tmp/cloudflared.deb \
    https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb && \
    dpkg -i /tmp/cloudflared.deb || apt-get install -f -y

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY src/ ./src/
COPY templates/ ./templates/
COPY static/ ./static/
COPY extensions/ ./extensions/

# Create data directory
RUN mkdir -p /data/sessions /data/replays

WORKDIR /app/src

EXPOSE 8080

CMD ["python", "app.py"]
