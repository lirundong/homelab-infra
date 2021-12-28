#!/bin/bash
set -ex
if [ ${EUID} -ne 0 ]; then
  echo "Please run as root"
  exit -1
fi

DNS_PORT="10053"
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
TUN_TABLE="101" # 100 was for TProxy routes.
TUN_MARK="0x02"

# I. IPv4 config.
#
# 1. Bypass local connectons.
for LOCAL_IP in ${LOCAL_IPS[@]}; do
  iptables -t mangle -A PREROUTING -d ${LOCAL_IP} -j RETURN
done
# 2. Do not touch DNS packets, as they will be handled by nat rules later.
iptables -t mangle -A PREROUTING -p udp --dport 53 -j RETURN
# 3. Mark all remaining connections and packets.
iptables -t mangle -A PREROUTING -j MARK --set-mark ${TUN_MARK}
# 4. Finally, take care of DNS packets.
iptables -t nat -A PREROUTING -p udp -m udp --dport 53 \
  -j REDIRECT --to-ports ${DNS_PORT}
# Routing configs are handled by clash_{start | stop}_post.sh scripts.

# II. IPv6 config.
for LOCAL_IP6 in ${LOCAL_IP6S[@]}; do
  ip6tables -t mangle -A PREROUTING -d ${LOCAL_IP6} -j RETURN
done
ip6tables -t mangle -A PREROUTING -p udp --dport 53 -j RETURN
ip6tables -t mangle -A PREROUTING -j MARK --set-mark ${TUN_MARK}
ip6tables -t nat -A PREROUTING -p udp -m udp --dport 53 \
  -j REDIRECT --to-ports ${DNS_PORT}
