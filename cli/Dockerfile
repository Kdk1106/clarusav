FROM python:3.11-slim

LABEL maintainer="ClarusAV Team"
LABEL description="ClarusAV CLI scanner container"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source tree and configuration
COPY pyproject.toml .
COPY configs/ configs/
COPY clarusav/ clarusav/

# Install clarusav in editable mode
RUN pip install --no-cache-dir -e .

ENTRYPOINT ["clarusav"]
CMD ["--help"]
