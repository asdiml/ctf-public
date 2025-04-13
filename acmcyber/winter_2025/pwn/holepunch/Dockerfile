FROM pwn.red/jail

COPY --from=ubuntu:22.04 / /srv
COPY holepunch /srv/app/run
COPY flag.txt /srv/app
RUN chmod 755 /srv/app/run
ENV JAIL_SYSCALLS=ptrace
