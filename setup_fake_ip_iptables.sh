#!/bin/bash
# https://github.com/Dreamacro/clash/issues/555#issuecomment-595064646

set -ex
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit -1
fi

REDIR_PORT="10082"
DNS_PORT="10053"
TPROXY_MARKER="0x01"

# TCP
iptables -t nat -N CLASH_LOCAL
iptables -t nat -A CLASH_LOCAL -m owner --uid-owner 1001 -j RETURN
iptables -t nat -A CLASH_LOCAL -d 0.0.0.0/8 -j RETURN
iptables -t nat -A CLASH_LOCAL -d 127.0.0.0/8 -j RETURN
iptables -t nat -A CLASH_LOCAL -d 224.0.0.0/4 -j RETURN
iptables -t nat -A CLASH_LOCAL -d 172.16.0.0/12 -j RETURN
iptables -t nat -A CLASH_LOCAL -d 127.0.0.0/8 -j RETURN
iptables -t nat -A CLASH_LOCAL -d 169.254.0.0/16 -j RETURN
iptables -t nat -A CLASH_LOCAL -d 240.0.0.0/4 -j RETURN
iptables -t nat -A CLASH_LOCAL -d 192.168.0.0/16 -j RETURN
iptables -t nat -A CLASH_LOCAL -d 10.0.0.0/8 -j RETURN
iptables -t nat -A CLASH_LOCAL -p tcp -j REDIRECT --to-ports ${REDIR_PORT}
iptables -t nat -I OUTPUT -p tcp -j CLASH_LOCAL

iptables -t nat -N CLASH_EXTERNAL
iptables -t nat -A CLASH_EXTERNAL -d 0.0.0.0/8 -j RETURN
iptables -t nat -A CLASH_EXTERNAL -d 127.0.0.0/8 -j RETURN
iptables -t nat -A CLASH_EXTERNAL -d 224.0.0.0/4 -j RETURN
iptables -t nat -A CLASH_EXTERNAL -d 172.16.0.0/12 -j RETURN
iptables -t nat -A CLASH_EXTERNAL -d 127.0.0.0/8 -j RETURN
iptables -t nat -A CLASH_EXTERNAL -d 169.254.0.0/16 -j RETURN
iptables -t nat -A CLASH_EXTERNAL -d 240.0.0.0/4 -j RETURN
iptables -t nat -A CLASH_EXTERNAL -d 192.168.0.0/16 -j RETURN
iptables -t nat -A CLASH_EXTERNAL -d 10.0.0.0/8 -j RETURN
iptables -t nat -A CLASH_EXTERNAL -p tcp -j REDIRECT --to-ports ${REDIR_PORT}
iptables -t nat -I PREROUTING -p tcp -j CLASH_EXTERNAL

# UDP
ip rule add fwmark ${TPROXY_MARKER} table 100
ip route add local default dev lo table 100
iptables -t mangle -N CLASH_UDP
iptables -t mangle -A CLASH_UDP -m owner --uid-owner 1001 -j RETURN
iptables -t mangle -A CLASH_UDP -d 0.0.0.0/8 -j RETURN
iptables -t mangle -A CLASH_UDP -d 10.0.0.0/8 -j RETURN
iptables -t mangle -A CLASH_UDP -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A CLASH_UDP -d 169.254.0.0/16 -j RETURN
iptables -t mangle -A CLASH_UDP -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A CLASH_UDP -d 192.168.0.0/16 -j RETURN
iptables -t mangle -A CLASH_UDP -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A CLASH_UDP -d 240.0.0.0/4 -j RETURN
iptables -t mangle -A CLASH_UDP -p udp -j TPROXY --on-port ${REDIR_PORT} --tproxy-mark ${TPROXY_MARKER}
iptables -t mangle -I PREROUTING -p udp -j CLASH_UDP

# DNS
iptables -t nat -N CLASH_DNS_LOCAL
iptables -t nat -A CLASH_DNS_LOCAL -p udp ! --dport 53 -j RETURN
iptables -t nat -A CLASH_DNS_LOCAL -m owner --uid-owner 1001 -j RETURN
iptables -t nat -A CLASH_DNS_LOCAL -p udp -j REDIRECT --to-ports ${DNS_PORT}
iptables -t nat -I OUTPUT -p udp -j CLASH_DNS_LOCAL

iptables -t nat -N CLASH_DNS_EXTERNAL
iptables -t nat -A CLASH_DNS_EXTERNAL -p udp ! --dport 53 -j RETURN
iptables -t nat -A CLASH_DNS_EXTERNAL -p udp -j REDIRECT --to-ports ${DNS_PORT}
iptables -t nat -I PREROUTING -p udp -j CLASH_DNS_EXTERNAL

# fake IP
iptables -t nat -I OUTPUT -p tcp -d 198.18.0.0/16 -j REDIRECT --to-port ${REDIR_PORT}
iptables -t mangle -I OUTPUT -p udp -d 198.18.0.0/16 -j MARK --set-mark ${TPROXY_MARKER}
