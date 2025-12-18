FROM golang:1.24

WORKDIR /app

# Install Python and pip
RUN apt-get update && \
    apt-get install -y python3 python3-pip python3-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY bin/backend /app/backend
COPY collector /app/collector

# Install Python dependencies if requirements.txt exists
RUN if [ -f /app/collector/requirements.txt ]; then \
    pip3 install --no-cache-dir --break-system-packages -r /app/collector/requirements.txt; \
    fi

# Create directory for observability data
RUN mkdir -p /app/observability-data

EXPOSE 8080

CMD ["/app/backend"]
