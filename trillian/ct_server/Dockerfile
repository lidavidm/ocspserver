FROM scratch

ADD ct_server /
ADD log_config.json /

ENV PORT 80
EXPOSE 80
ENTRYPOINT ["/ct_server", "-log_config",  "/log_config.json", "-log_dir", "/"]

