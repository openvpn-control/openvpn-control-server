FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache openssl libc6-compat

COPY package*.json ./
RUN npm install

COPY prisma ./prisma
RUN npx prisma generate

COPY src ./src

EXPOSE 8080

CMD ["node", "src/index.js"]
