FROM node:20-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends chromium ca-certificates fonts-liberation \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY src ./src

ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
EXPOSE 5000
CMD ["npm", "start"]
