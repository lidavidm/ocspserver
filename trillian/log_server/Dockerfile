FROM scratch
ADD main /
VOLUME ["/config"]
ENV DB_USER root
ENV DB_PASS=
ENV DB_HOST db
ENV DB_PORT 3306
ENV DB_NAME trillian
ENV PRIVATE_KEY_FILE /config/privkey.pem
ENV PRIVATE_KEY_PASSWORD=
# Use ENTRYPOINT so that the user can pass in additional arguments to the server
# There's no /tmp dir and no shell to make one, so just log to root
ENTRYPOINT ["/main", "-mysql_uri", "$DB_USER:$DB_PASS@tcp($DB_HOST:$DB_PORT)/$DB_NAME", "-private_key_file", "$PRIVATE_KEY_FILE", "-private_key_password", "$PRIVATE_KEY_PASSWORD", "-log_dir", "/"]
CMD []