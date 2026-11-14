FROM python:3.11-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --create-home signal \
    && mkdir -p /var/lib/signal && chown signal:signal /var/lib/signal
ENV SIGNAL_DATA_DIR=/var/lib/signal
VOLUME ["/var/lib/signal"]
USER signal
EXPOSE 8765
ENTRYPOINT ["signal-oss", "serve", "--host", "0.0.0.0", "--port", "8765"]
