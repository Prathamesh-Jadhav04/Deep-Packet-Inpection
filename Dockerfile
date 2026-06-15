FROM python:3.9-slim

WORKDIR /app

# Install system dependencies (including libpcap-dev in case Scapy runs in fallback)
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend files
COPY dpi_engine/ ./dpi_engine/
COPY models/ ./models/
COPY cli.py .
COPY dpi_engine.py .
COPY test_dpi.pcap .

# Expose Hugging Face Space port (7860)
EXPOSE 7860

# Run Python server binding to port 7860
CMD ["python", "dpi_engine.py", "--dashboard", "--dashboard-host", "0.0.0.0", "--dashboard-port", "7860"]
