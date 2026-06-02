FROM python:3.11-slim

LABEL org.opencontainers.image.title="spring2shell"
LABEL org.opencontainers.image.description="CVE scanner and exploitation toolkit for Spring/GraphQL/React stacks"
LABEL org.opencontainers.image.source="https://github.com/your-org/spring2shell"

# Non-root user for security
RUN groupadd -r spring2shell && useradd -r -g spring2shell spring2shell

WORKDIR /app

# Install system deps (nslookup/dig for OOB tests)
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    dnsutils curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer caching)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy project source
COPY pyproject.toml ./
COPY src/ ./src/
COPY data/ ./data/
COPY configs/ ./configs/

# Install the package
RUN pip install --no-cache-dir -e .

# Create reports directory
RUN mkdir -p /app/reports /app/logs && \
    chown -R spring2shell:spring2shell /app/reports /app/logs

USER spring2shell

VOLUME ["/app/reports", "/app/logs"]

ENTRYPOINT ["spring2shell"]
CMD ["--help"]
