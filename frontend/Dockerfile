# Сборка панели (Vite). Рантайм — только nginx:alpine.
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci \
  && npm cache clean --force

COPY . .
RUN npm run build \
  && find /app/dist -name '*.map' -delete

FROM nginx:1.27-alpine

RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/panel.conf
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN sed -i 's/\r$//' /docker-entrypoint.sh && chmod +x /docker-entrypoint.sh

COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 8080
ENTRYPOINT ["/docker-entrypoint.sh"]
