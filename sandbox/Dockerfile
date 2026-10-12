FROM python:3.11-slim

LABEL maintainer="ClarusAV Team"
LABEL description="Disposable Wine execution environment with psutil/watchdog monitor"

# Install Wine and monitoring prerequisites
RUN apt-get update && apt-get install -y --no-install-recommends \
    wine \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /sandbox

# Install monitor agent dependencies
RUN pip install --no-cache-dir psutil==7.2.2 watchdog==6.0.0

COPY monitor.py /sandbox/monitor.py

# Create non-root unprivileged execution user
RUN useradd -m -s /bin/bash sandboxuser && \
    mkdir -p /workspace && \
    chown -R sandboxuser:sandboxuser /workspace /sandbox

USER sandboxuser
WORKDIR /workspace

ENTRYPOINT ["python3", "/sandbox/monitor.py"]
