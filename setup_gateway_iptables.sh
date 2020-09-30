#!/bin/bash
set -ex
if [ ${EUID} -ne 0 ]; then
  echo "Please run as root"
  exit -1
fi

REDIR_PORT="10082"
DNS_PORT="10053"
TPROXY_MARKER="0x01"
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

# Let's start with mangle table:
# 1. Do not touch UDP packets which destinate to other LAN devices.
for LOCAL_IP in ${LOCAL_IPS}; do
  iptables -t mangle -A PREROUTING -d ${LOCAL_IP} -p udp -j RETURN
done
# 2. Do not touch DNS packets, as they will be handled by nat rules later.
iptables -t mangle -A PREROUTING -p udp -m udp --dport 53 -j RETURN
# 3. Redirect all other UDP packets to a localhost socket which is listening on 
#    REDIR_PORT, and mark these packets with TPROXY_MARKER...
iptables -t mangle -A PREROUTING -p udp -j TPROXY \
  --on-port ${REDIR_PORT} --on-ip 127.0.0.1 --tproxy-mark ${TPROXY_MARKER}
# 3.1. ...then route these marked packets to local loopback device, such that 
#    application out of the kernel listening on REDIR_PORT (i.e. clash) can 
#    intercept these UDP packets.
#    Ref: https://powerdns.org/tproxydoc/tproxy.md.html
ip rule add fwmark ${TPROXY_MARKER} table ${ROUTING_TABLE}
ip route add local default dev lo table ${ROUTING_TABLE}

# The nat table part is much easier:
# 1. Redirect all DNS packets, regardless of their destination, to DNS_PORT 
#    on localhost so clients can get fake-ip responses.
iptalbes -t nat -A PREROUTING -p udp -m udp --dport 53 \
  -j REDIRECT --to-ports ${DNS_PORT}
# 2. Do not touch TCP packets which destinate to other LAN devices.
for LOCAL_IP in ${LOCAL_IPS}; do
  iptalbes -t nat -A PREROUTING -d ${LOCAL_IP} -p tcp -j RETURN
done
# 3. Finally redirect all other TCP packets to REDIR_PORT on localhost.
iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-ports ${REDIR_PORT}
