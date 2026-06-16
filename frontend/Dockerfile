# Stage 1: Build stage
FROM node:18-alpine AS build

WORKDIR /app

# Copy package configurations and install dependencies
COPY package*.json ./
RUN npm install

# Copy application files and compile
COPY . .
RUN npm run build

# Stage 2: Nginx serving stage
FROM nginx:alpine

# Copy Nginx configuration file
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy build output to serving root
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
