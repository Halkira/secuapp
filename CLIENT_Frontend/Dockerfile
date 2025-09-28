FROM node:18 AS frontend-builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . ./

# Au lieu d'utiliser sed, créons un package.json temporaire avec les bonnes valeurs
RUN npm pkg set scripts.build="tsc --noEmit && vite build"
RUN npm pkg set scripts.lint="eslint src"

RUN CI=false npm run build

# Étape 2 : serveur nginx pour servir les fichiers statiques
FROM nginx:alpine
COPY --from=frontend-builder /app/dist /usr/share/nginx/html
COPY default.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]