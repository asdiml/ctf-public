FROM ubuntu:22.04 AS app

FROM pwn.red/jail

COPY --from=app / /srv
COPY ghast flag.txt /srv/app/
COPY shade /srv/app/run
RUN chmod 755 /srv/app/run

ENV JAIL_SYSCALLS=ptrace
