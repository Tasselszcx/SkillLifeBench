FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 sandbox && \
    mkdir -p /workspace /results && \
    chown -R sandbox:sandbox /workspace /results

# Install Python dependencies
COPY requirements-sandbox.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements-sandbox.txt

# Security: Drop capabilities, read-only root
USER sandbox
WORKDIR /workspace

# Entry point for agent execution
COPY entrypoint.py /usr/local/bin/
ENTRYPOINT ["python", "/usr/local/bin/entrypoint.py"]
