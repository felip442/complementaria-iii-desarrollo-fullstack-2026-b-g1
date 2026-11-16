# Dockerfile — Backend Node.js + Express
FROM node:20-alpine

# Carpeta de trabajo dentro del contenedor
WORKDIR /app

# 1) Dependencias primero (aprovecha la caché de capas de Docker)
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# 2) Código fuente
COPY src ./src

# Modo producción
ENV NODE_ENV=production
ENV PORT=3000

# No ejecutar como root
USER node

# Puerto de la API
EXPOSE 3000

# Verifica que la API responda (requiere una ruta GET /health)
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:${PORT}/health || exit 1

# Arranque
CMD ["node", "src/server.js"]

# Los secretos (JWT_SECRET, DATABASE_URL, etc.) NO van aquí:
# se pasan al ejecutar:  docker run --env-file .env -p 3000:3000 mi-backend:1.0
