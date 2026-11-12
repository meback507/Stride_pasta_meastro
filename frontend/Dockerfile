# Frontend Production Serving via Nginx
FROM nginx:alpine

# Copy static frontend assets directly to Nginx web root
COPY ../backend/static /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
