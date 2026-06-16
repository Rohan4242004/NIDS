FROM python:3.10-slim

WORKDIR /app

# Install system dependencies required for packet sniffing (libpcap) and package compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    libc6-dev \
    make \
    && rm -rf /var/lib/apt/lists/*

# Copy python dependencies list and install them
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application source files
COPY . .

EXPOSE 8000

# Start API server via Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
