FROM scratch

VOLUME ["/config"]
ADD main /
ADD trampoline /

# Use ENTRYPOINT so that the user can pass in additional arguments to the server
# There's no /tmp dir and no shell to make one, so just log to root
ENTRYPOINT ["/trampoline", "--target", "/main", "--config", "/config/ct.json"]
CMD []
