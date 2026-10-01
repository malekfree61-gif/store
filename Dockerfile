FROM node:24-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
ENV NODE_ENV=production
ENV DATA_DIR=/var/data
ENV HOST=0.0.0.0
EXPOSE 3000
CMD ["npm", "start"]