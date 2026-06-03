# Prod: только runtime-зависимости + Prisma CLI для migrate при старте.
FROM node:20-alpine AS build

WORKDIR /app

COPY package*.json prisma ./
RUN npm ci \
  && npx prisma generate \
  && npm cache clean --force

FROM node:20-alpine

WORKDIR /app

ENV NODE_ENV=production

RUN apk add --no-cache openssl libc6-compat wget

COPY package*.json ./
RUN npm ci --omit=dev \
  && npm cache clean --force

COPY --from=build /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=build /app/node_modules/@prisma/client ./node_modules/@prisma/client
COPY --from=build /app/node_modules/prisma ./node_modules/prisma
COPY --from=build /app/node_modules/.bin/prisma ./node_modules/.bin/prisma

COPY prisma ./prisma
COPY src ./src
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN sed -i 's/\r$//' /docker-entrypoint.sh && chmod +x /docker-entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["node", "src/index.js"]
