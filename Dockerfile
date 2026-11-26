FROM node:24-bookworm-slim

WORKDIR /app
ENV NODE_ENV=production PORT=8787

COPY package.json package-lock.json ./
COPY vendor ./vendor
RUN npm ci --omit=dev

COPY dist ./dist

EXPOSE 8787
CMD ["node", "dist/index.js"]
