FROM mariadb:10.1

ADD init.sql /docker-entrypoint-initdb.d/init.sql
ENV MYSQL_ALLOW_EMPTY_PASSWORD 1