FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep
RUN pip install --no-cache-dir semgrep

# Set working directory
WORKDIR /app

# Copy project files
COPY pyproject.toml ./
COPY src/ ./src/
COPY config/ ./config/

# Install the project
RUN pip install --no-cache-dir -e ".[dev]"

# Expose API port
EXPOSE 8000

# Default command: start the API server
CMD ["sse", "server", "--host", "0.0.0.0", "--port", "8000"]
