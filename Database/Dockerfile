FROM mysql:5.7
WORKDIR /setup
USER root
COPY setup.sql /docker-entrypoint-initdb.d/

#RUN mysql -p test -u root --password=password < setup.sql