
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Install the tools needed to compile the C++ engine
RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

# Install Flask and Gunicorn
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the project source
COPY . .

# Build the engine and generate sample packets
RUN make all \
    && python generate_test_pcap.py \
    && test -x ./dpi_engine \
    && test -s test_dpi.pcap

# Start the Flask dashboard
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-10000} dashboard:app"]
