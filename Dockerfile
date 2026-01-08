# Multi-stage build for CyberSec Terminal
FROM python:3.11-slim as builder

# Set build arguments
ARG VERSION=2.0.0
ARG BUILD_DATE
ARG VCS_REF

# Labels for metadata
LABEL org.opencontainers.image.title="CyberSec Terminal" \
      org.opencontainers.image.description="Professional Cybersecurity Analysis Platform" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/morgang213/cs-pro" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="MIT"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim as production

# Set Python version as build arg for flexibility
ARG PYTHON_VERSION=3.11

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python${PYTHON_VERSION}/site-packages /usr/local/lib/python${PYTHON_VERSION}/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application files
COPY . .

# Create non-root user for security
RUN useradd -m -u 1000 cybersec && \
    chown -R cybersec:cybersec /app

# Switch to non-root user
USER cybersec

# Expose ports
EXPOSE 5000 5500

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=5000

# Default command - run web terminal
CMD ["python", "terminal_web.py"]
