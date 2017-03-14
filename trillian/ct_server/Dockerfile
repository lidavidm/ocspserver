FROM scratch

VOLUME ["/config"]
ADD main /

ENV PORT 80
EXPOSE 80
ENTRYPOINT ["/main", "-log_config",  "/config/log_config.json", "-log_dir", "/"]
