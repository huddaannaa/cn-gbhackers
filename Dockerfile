FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
RUN mkdir -p /app/archives

# Default envs (override in compose)
ENV ES_BASE_URL=https://es1.local:9200 \
    ES_INDEX=pr-gbhacker_cve \
    ES_USERNAME=elastic \
    ES_PASSWORD=changeme \
    ES_VERIFY=false \
    ES_BULK_CHUNK=500

# Run once and exit
ENTRYPOINT ["python", "-u", "app/scraper.py"]
