FROM nginx:stable

RUN apt-get update && apt-get install -y curl openssl

COPY nginx.conf /etc/nginx/nginx.conf
COPY certs/server-fullchain.pem /etc/ssl/certs/server-fullchain.pem
COPY certs/MTLS.key /etc/ssl/private/MTLS.key
COPY certs/ca-chain.pem /etc/ssl/certs/ca-chain.pem

COPY crl/interCA.pem /usr/local/interCA.pem

COPY crl/ca-chain.crl /etc/nginx/crl/ca-chain.crl
COPY crl/new_crl.sh /usr/local/bin/new_crl.sh
RUN chmod +x /usr/local/bin/new_crl.sh

EXPOSE 443

CMD /usr/local/bin/new_crl.sh & nginx -g 'daemon off;'

