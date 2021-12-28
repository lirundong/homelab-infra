#!/bin/bash
set -ex
if [ ${EUID} -ne 0 ]; then
  echo "Please run as root"
  exit -1
fi

REDIR_PORT="10082"
DNS_PORT="10053"
TPROXY_MARKER="0x01"
TPROXY_PORT="10083"
ROUTING_TABLE="100"
LOCAL_IPS=(
  "0.0.0.0/8"
  "10.0.0.0/8"
  "127.0.0.0/8"
  "169.254.0.0/16"
  "172.16.0.0/12"
  "192.168.0.0/16"
  "224.0.0.0/4"
  "240.0.0.0/4"
)
LOCAL_IP6S=(
  "::/128"
  "::1/128"
  "::ffff:0:0/96"
  "::ffff:0:0:0/96"
  "64:ff9b::/96"
  "100::/64"
  "2001::/32"
  "2001:20::/28"
  "2001:db8::/32"
  "2002::/16"
  "fc00::/7"
  "fe80::/10"
  "ff00::/8"
)

# I. IPv4 config.
#
# Let's start with mangle table:
# 1. Do not touch UDP packets which destinate to other LAN devices.
for LOCAL_IP in ${LOCAL_IPS[@]}; do
  iptables -t mangle -A PREROUTING -d ${LOCAL_IP} -j RETURN
done
# 2. Do not touch DNS packets, as they will be handled by nat rules later.
iptables -t mangle -A PREROUTING -p udp --dport 53 -j RETURN
# 3. Redirect all other UDP packets and TCP connections to a localhost socket
#    which is listening on  TPROXY_PORT, and mark these packets with
#    TPROXY_MARKER...
iptables -t mangle -A PREROUTING -p tcp -j TPROXY --on-port ${TPROXY_PORT} \
  --tproxy-mark ${TPROXY_MARKER}
iptables -t mangle -A PREROUTING -p udp -j TPROXY --on-port ${TPROXY_PORT} \
  --tproxy-mark ${TPROXY_MARKER}
# 3.1. ...then route these marked packets to local loopback device, such that 
#    application out of the kernel listening on REDIR_PORT (i.e. clash) can 
#    intercept these UDP packets.
#    Ref: https://powerdns.org/tproxydoc/tproxy.md.html
ip rule add fwmark ${TPROXY_MARKER} table ${ROUTING_TABLE}
ip route add local default dev lo table ${ROUTING_TABLE}
# 4. The nat table part is much easier, as we only need to handle DNS packets:
#    Redirect all DNS packets, regardless of their destinations, to DNS_PORT 
#    on localhost so clients can get fake-ip responses.
iptables -t nat -A PREROUTING -p udp -m udp --dport 53 \
  -j REDIRECT --to-ports ${DNS_PORT}

# II. IPv6 config.
#
# The steps are similar to their IPv4 counterparts, so we omit comments here.
for LOCAL_IP6 in ${LOCAL_IP6S[@]}; do
  ip6tables -t mangle -A PREROUTING -d ${LOCAL_IP6} -j RETURN
done
ip6tables -t mangle -A PREROUTING -p udp --dport 53 -j RETURN
ip6tables -t mangle -A PREROUTING -p tcp -j TPROXY --on-port ${TPROXY_PORT} \
  --tproxy-mark ${TPROXY_MARKER}
ip6tables -t mangle -A PREROUTING -p udp -j TPROXY --on-port ${TPROXY_PORT} \
  --tproxy-mark ${TPROXY_MARKER}
ip -6 rule add fwmark ${TPROXY_MARKER} table ${ROUTING_TABLE}
ip -6 route add local default dev lo table ${ROUTING_TABLE}
ip6tables -t nat -A PREROUTING -p udp -m udp --dport 53 \
  -j REDIRECT --to-ports ${DNS_PORT}
