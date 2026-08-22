# Disposable Linux guest used as a micro-VM equivalent:
# tiny userspace, ptrace-enabled, loopback-only, memory-capped at run time.
FROM alpine:3.20
RUN apk add --no-cache strace build-base python3 bash coreutils
WORKDIR /guest
CMD ["/bin/sh"]
