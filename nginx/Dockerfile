# Edge nginx без certbot (~45 MB). HTTPS: свой сертификат в volume или profile ssl.
FROM nginx:1.27-alpine

RUN apk add --no-cache openssl

COPY entrypoint.sh /entrypoint.sh
COPY conf.d/ /etc/nginx/templates/

RUN sed -i 's/\r$//' /entrypoint.sh \
  && chmod +x /entrypoint.sh \
  && mkdir -p /var/www/certbot /etc/nginx/conf.d/snippets \
  && rm -f /etc/nginx/conf.d/default.conf

EXPOSE 80 443

ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
