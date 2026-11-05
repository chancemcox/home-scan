FROM python:3.14-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN pip install --no-cache-dir tplink-deco-api==2.1.0
COPY app.py storage.py cloudflare_sync.py ws.py ha.py auth.py index.html login.html login.js app.js style.css deco.py ./
ENV PYTHONUNBUFFERED=1 DB_PATH=/data/homescan.db
VOLUME /data
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1/health', timeout=2)"
CMD ["python", "app.py"]

