FROM ubuntu:20.04 AS app

FROM pwn.red/jail

COPY --from=app / /srv
COPY flag.txt /srv/app/
COPY oneshot /srv/app/run
RUN chmod 755 /srv/app/run

ENV JAIL_TIME=60
