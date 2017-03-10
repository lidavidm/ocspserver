FROM scratch
ADD main /
ADD trampoline /
VOLUME ["/config"]
# Use ENTRYPOINT so that the user can pass in additional arguments to the server
# There's no /tmp dir and no shell to make one, so just log to root
ENTRYPOINT ["/trampoline", "--target", "/main", "--config", "/config/log.json"]
CMD []