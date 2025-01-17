FROM ubuntu:22.04@sha256:3d1556a8a18cf5307b121e0a98e93f1ddf1f3f8e092f1fddfd941254785b95d7
ENV DEBIAN_FRONTEND noninteractive

# Challenge setup. Not important.
RUN apt-get -y update --fix-missing && \
    apt-get -y install xinetd
RUN groupadd -r pwn && useradd -r -g pwn pwn

RUN echo '#!/bin/bash\n\
service xinetd restart && /bin/sleep infinity' > /etc/init.sh
RUN echo 'service pwn\n\
{\n\
  type = UNLISTED\n\
  disable = no\n\
  socket_type = stream\n\
  protocol = tcp\n\
  wait = no\n\
  user = pwn\n\
  bind = 0.0.0.0\n\
  port = 9999\n\
  server = /home/pwn/catcpy\n\
}' > /etc/xinetd.d/pwn
RUN chmod 500 /etc/init.sh
RUN chmod 444 /etc/xinetd.d/pwn
RUN chmod 1733 /tmp /var/tmp /dev/shm

# The flag is here
RUN echo "Alpaca{*** REDACTED ***}" > /flag.txt
RUN chmod 444 /flag.txt

WORKDIR /home/pwn
ADD --chmod=550 catcpy .

# The challenge is working on port 9999
RUN chown -R root:pwn /home/pwn
RUN service xinetd restart
