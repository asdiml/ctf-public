FROM pwn.red/jail

COPY --from=ubuntu:22.04 / /srv
COPY weakbox /srv/app/run
COPY flag.txt /srv/app
RUN chmod 755 /srv/app/run
ENV JAIL_SYSCALLS=ptrace JAIL_TIME=120 JAIL_CPU=1000
