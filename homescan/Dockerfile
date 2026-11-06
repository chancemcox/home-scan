FROM node:24-bookworm-slim
ARG HOMESCAN_PUSH=unknown
RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json server.js index.html login.html login.js app.js style.css ./
COPY lib ./lib
RUN printf '%s\n' "$HOMESCAN_PUSH" > /app/PUSH
ENV DB_PATH=/data/homescan.db HOMESCAN_PUSH=$HOMESCAN_PUSH HASS_INGRESS=1 PORT=8099
EXPOSE 8099
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "fetch('http://127.0.0.1:8099/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.js"]
