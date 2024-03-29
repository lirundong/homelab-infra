FROM ubuntu:18.04

ENV REDIR_PORT=10082
ARG CLASH_ROOT=/root/.config/clash
ARG CLASH_RELEASE=v1.1.0

WORKDIR /root

SHELL ["/bin/bash", "-c"]

RUN echo $' \n\
  deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic main restricted universe multiverse \n\
  deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic-updates main restricted universe multiverse \n\
  deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic-backports main restricted universe multiverse \n\
  deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic-security main restricted universe multiverse \n\
  ' > /etc/apt/sources.list && \
  apt-get update && \
  apt-get install --yes iproute2 iptables ca-certificates wget && \
  mkdir -p "$CLASH_ROOT" && \
  wget -O "$CLASH_ROOT/Country.mmdb" https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb && \
  wget https://github.com/Dreamacro/clash/releases/download/$CLASH_RELEASE/clash-linux-amd64-$CLASH_RELEASE.gz && \
  gzip -d clash-linux-amd64-$CLASH_RELEASE.gz && \
  mv clash-linux-amd64-$CLASH_RELEASE /usr/local/bin/clash && \
  chmod +x /usr/local/bin/clash && \
  rm -rf /var/lib/apt/lists/*

CMD local_ipv4=$( \
    ip a | \
    grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | \
    grep -Eo '([0-9]*\.){3}[0-9]*' | \
    grep -v '127.0.0.1' \
  ) && \
  iptables -t nat -N CLASH && \
  iptables -t nat -A CLASH -d 0.0.0.0/8 -j RETURN && \
  iptables -t nat -A CLASH -d 10.0.0.0/8 -j RETURN && \
  iptables -t nat -A CLASH -d 127.0.0.0/8 -j RETURN && \
  iptables -t nat -A CLASH -d 169.254.0.0/16 -j RETURN && \
  iptables -t nat -A CLASH -d 172.16.0.0/12 -j RETURN && \
  iptables -t nat -A CLASH -d 192.168.0.0/16 -j RETURN && \
  iptables -t nat -A CLASH -d 224.0.0.0/4 -j RETURN && \
  iptables -t nat -A CLASH -d 240.0.0.0/4 -j RETURN && \
  iptables -t nat -A CLASH -d "$local_ipv4" -j RETURN && \
  iptables -t nat -A CLASH -p tcp -j REDIRECT --to-port "$REDIR_PORT" && \
  iptables -t nat -I PREROUTING -p tcp -d 8.8.8.8 -j REDIRECT --to-port "$REDIR_PORT" && \
  iptables -t nat -I PREROUTING -p tcp -d 8.8.4.4 -j REDIRECT --to-port "$REDIR_PORT" && \
  iptables -t nat -A PREROUTING -p tcp -j CLASH && \
  ip rule add fwmark 1 table 100 && \
  ip route add local default dev lo table 100 && \
  iptables -t mangle -N CLASH && \
  iptables -t mangle -A CLASH -d 0.0.0.0/8 -j RETURN && \
  iptables -t mangle -A CLASH -d 10.0.0.0/8 -j RETURN && \
  iptables -t mangle -A CLASH -d 127.0.0.0/8 -j RETURN && \
  iptables -t mangle -A CLASH -d 169.254.0.0/16 -j RETURN && \
  iptables -t mangle -A CLASH -d 172.16.0.0/12 -j RETURN && \
  iptables -t mangle -A CLASH -d 192.168.0.0/16 -j RETURN && \
  iptables -t mangle -A CLASH -d 224.0.0.0/4 -j RETURN && \
  iptables -t mangle -A CLASH -d 240.0.0.0/4 -j RETURN && \
  iptables -t mangle -A CLASH -d "$local_ipv4" -j RETURN && \
  iptables -t mangle -A PREROUTING -p udp -j CLASH && \
  /usr/local/bin/clash
