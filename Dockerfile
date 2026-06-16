# Stage 1: Build the Next.js Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/dashboard

# Copy package files and install dependencies
COPY dashboard/package*.json ./
RUN npm install --legacy-peer-deps

# Copy frontend source code
COPY dashboard/ ./

# Build Next.js app to static html export (dashboard/out)
RUN npm run build

# Stage 2: Build the Python Backend & Package Everything
FROM python:3.9-slim
WORKDIR /app

# Install system dependencies for network processing
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy backend requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code files
COPY dpi_engine/ ./dpi_engine/
COPY models/ ./models/
COPY cli.py .
COPY dpi_engine.py .
COPY test_dpi.pcap .

# Copy the compiled Next.js frontend assets from Stage 1
COPY --from=frontend-builder /app/dashboard/out ./dashboard/out

# Change ownership of /app to UID 1000 for Hugging Face permissions
RUN chown -R 1000:1000 /app

# Expose Hugging Face Space default port
EXPOSE 7860

# Start Python server, binding it to Hugging Face's port 7860
CMD ["python", "dpi_engine.py", "--dashboard", "--dashboard-host", "0.0.0.0", "--dashboard-port", "7860"]
