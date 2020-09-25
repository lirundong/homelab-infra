FROM alpine:latest

ENV REDIR_PORT=10082 \
  DNS_PORT=10053

ARG CLASH_ROOT=/root/.config/clash
ARG CLASH_RELEASE=v1.1.0

WORKDIR /root

RUN apk add --no-cache iproute2 ca-certificates && \
  mkdir -p "$CLASH_ROOT" && \
  wget -O "$CLASH_ROOT/Country.mmdb" https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb && \
  wget https://github.com/Dreamacro/clash/releases/download/$CLASH_RELEASE/clash-linux-amd64-$CLASH_RELEASE.gz && \
  gzip -d clash-linux-amd64-$CLASH_RELEASE.gz && \
  mv clash-linux-amd64-$CLASH_RELEASE /usr/local/bin/clash && \
  chmod +x /usr/local/bin/clash 

CMD local_ipv4=$( \
    ifconfig | \
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
  iptables -t mangle -A CLASH -p udp -j TPROXY --on-port "$REDIR_PORT" --tproxy-mark 1 && \
  iptables -t mangle -A PREROUTING -p udp -j CLASH && \
  iptables -t nat -N CLASH_DNS && \
  iptables -t nat -F CLASH_DNS  && \
  iptables -t nat -A CLASH_DNS -p udp -j REDIRECT --to-port "$DNS_PORT" && \
  iptables -t nat -I OUTPUT -p udp --dport 53 -j CLASH_DNS && \
  iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to "$DNS_PORT"

ENTRYPOINT ["/usr/local/bin/clash"]