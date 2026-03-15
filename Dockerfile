FROM node:22-alpine

WORKDIR /app

COPY package.json ./
COPY server.mjs ./

ENV NODE_ENV=production

EXPOSE 3001

CMD ["node", "server.mjs"]
