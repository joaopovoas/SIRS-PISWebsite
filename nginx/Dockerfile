FROM nginx
COPY ./nginx.conf /etc/nginx/nginx.conf
COPY ./certs/nginx-selfsigned.crt /etc/ssl/certs/nginx-selfsigned.crt
COPY ./private/nginx-selfsigned.key /etc/ssl/private/nginx-selfsigned.key
COPY ./self-signed.conf /etc/nginx/snippets/self-signed.conf
COPY ./ssl-params.conf /etc/nginx/snippets/ssl-params.conf
COPY ./dhparam.pem /etc/nginx/dhparam.pem