FROM node:20-alpine AS builder

WORKDIR /app

RUN npm install -g pnpm

COPY apps/dashboard/package.json ./
RUN pnpm install

COPY apps/dashboard/ ./
RUN pnpm build

FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

COPY --from=builder /app/package.json ./
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/node_modules ./node_modules

EXPOSE 3000

USER node

CMD ["node_modules/.bin/next", "start"]
