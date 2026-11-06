FROM python:3.14-slim
ARG HOMESCAN_PUSH=unknown
RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN pip install --no-cache-dir tplink-deco-api==2.1.0
COPY app.py storage.py cloudflare_sync.py ws.py ha.py auth.py d1.py do_db.py cluster_state.py applog.py index.html login.html login.js app.js style.css deco.py ./
RUN printf '%s\n' "$HOMESCAN_PUSH" > /app/PUSH
ENV PYTHONUNBUFFERED=1 DB_PATH=/data/homescan.db HOMESCAN_PUSH=$HOMESCAN_PUSH HASS_INGRESS=1 PORT=8099
EXPOSE 8099
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8099/health', timeout=2)"
CMD ["python", "app.py"]
