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

# Copy application artifacts from the build context in a way that tolerates missing optional directories
COPY . /tmp/build-context
RUN mkdir -p /app/src /app/templates /app/static /app/extensions /app/scripts \
    && if [ -d /tmp/build-context/src ]; then cp -R /tmp/build-context/src/. /app/src/; fi \
    && if [ -d /tmp/build-context/templates ]; then cp -R /tmp/build-context/templates/. /app/templates/; fi \
    && if [ -d /tmp/build-context/static ]; then cp -R /tmp/build-context/static/. /app/static/; fi \
    && if [ -d /tmp/build-context/extensions ]; then cp -R /tmp/build-context/extensions/. /app/extensions/; fi \
    && if [ -d /tmp/build-context/scripts ]; then cp -R /tmp/build-context/scripts/. /app/scripts/; fi \
    && rm -rf /tmp/build-context

# Create data directory
RUN mkdir -p /data/sessions /data/replays

WORKDIR /app/src

EXPOSE 8080

CMD ["python", "app.py"]
