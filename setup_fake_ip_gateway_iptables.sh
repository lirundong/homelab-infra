#!/bin/bash
set -ex
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit -1
fi

REDIR_PORT="10082"
DNS_PORT="10053"
TPROXY_MARKER="0x01"
ROUTING_TABLE="100"
FAKE_IP="198.18.0.0/16"

# redirect inbound DNS packets
iptables -t nat -A INPUT -p udp --dport 53 -j REDIRECT --to-ports ${DNS_PORT}

# redirect forwarding traffic with fake ip
iptables -t nat -A PREROUTING -p tcp -d ${FAKE_IP} -j REDIRECT --to-ports ${REDIR_PORT}
iptables -t mangle -A PREROUTING -p udp -d ${FAKE_IP} -j TPROXY --on-port ${REDIR_PORT} --tproxy-mark ${TPROXY_MARKER}
ip rule add fwmark ${TPROXY_MARKER} table ${ROUTING_TABLE}
ip route add local default dev lo table ${ROUTING_TABLE}
