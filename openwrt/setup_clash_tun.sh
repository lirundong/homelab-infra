#!/bin/bash
#
# Copy this script to /etc/firewall.user so firewall can auto-load this.
set -ex
if [ ${EUID} -ne 0 ]; then
  echo "Please run as root"
  exit -1
fi

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
DIRECT_MACS=(
  "00:11:32:ac:77:2e" # synonas eth0
)
TUN_MARK="0x02"
DNS_MARK="0x03"
DNS_PORT="10053"
LAN_DEV="br-lan"
WAN_DEV="pppoe-wan"
TUN_DEV="utun"

# IPv4 config.
# Filter table.
#
# 0. Accept TUN to LAN, WAN forwards.
rule_idx="1"
iptables -t filter -I FORWARD $(( rule_idx++ )) -i ${LAN_DEV} -o ${TUN_DEV} -j ACCEPT
iptables -t filter -I FORWARD $(( rule_idx++ )) -i ${TUN_DEV} -o ${LAN_DEV} -j ACCEPT
# Mangle table.
#
# 1. Bypass local connectons.
local_ipv4="local_ipv4"
rule_idx="1"
ipset create ${local_ipv4} hash:net >/dev/null 2>&1
for LOCAL_IP in ${LOCAL_IPS[@]}; do
  ipset add ${local_ipv4} ${LOCAL_IP}
done
iptables -t mangle -I PREROUTING $(( rule_idx++ )) -i ${LAN_DEV} -m set --match-set ${local_ipv4} dst -j RETURN
# 2. Do not touch direct-to-wan packets.
for MAC in ${DIRECT_MACS[@]}; do
  iptables -t mangle -I PREROUTING $(( rule_idx++ )) -i ${LAN_DEV} -m mac --mac-source ${MAC} -j RETURN 
done
# 3. Mark and accept DNS packets, they will be redirted to Clash DNS port by NAT rules later.
iptables -t mangle -I PREROUTING $(( rule_idx++ )) -p udp --dport 53 -j MARK --set-mark ${DNS_MARK}
iptables -t mangle -I PREROUTING $(( rule_idx++ )) -p udp --dport 53 -j RETURN
# 3. Mark all remaining packets and route them to TUN later.
iptables -t mangle -I PREROUTING $(( rule_idx++ )) -i ${LAN_DEV} -j MARK --set-mark ${TUN_MARK}
# NAT table.
#
# 1. Finally, take care of DNS packets.
rule_idx="1"
iptables -t nat -I PREROUTING $(( rule_idx++ )) -p udp --dport 53 -m mark --mark ${DNS_MARK} -j REDIRECT --to-ports ${DNS_PORT}

# IPv6 config.
rule_idx="1"
ip6tables -t filter -I FORWARD $(( rule_idx++ )) -i ${LAN_DEV} -o ${TUN_DEV} -j ACCEPT
ip6tables -t filter -I FORWARD $(( rule_idx++ )) -i ${TUN_DEV} -o ${LAN_DEV} -j ACCEPT
local_ipv6="local_ipv6"
ipset create ${local_ipv6} hash:net family inet6 >/dev/null 2>&1
for LOCAL_IP6 in ${LOCAL_IP6S[@]}; do
  ipset add ${local_ipv6} ${LOCAL_IP6}
done
rule_idx="1"
for MAC in ${DIRECT_MACS[@]}; do
  ip6tables -t mangle -I PREROUTING $(( rule_idx++ )) -i ${LAN_DEV} -m mac --mac-source ${MAC} -j RETURN 
done
ip6tables -t mangle -I PREROUTING $(( rule_idx++ )) -p udp --dport 53 -j MARK --set-mark ${DNS_MARK}
ip6tables -t mangle -I PREROUTING $(( rule_idx++ )) -p udp --dport 53 -j RETURN
ip6tables -t mangle -I PREROUTING $(( rule_idx++ )) -i ${LAN_DEV} -m set --match-set ${local_ipv6} dst -j RETURN
ip6tables -t mangle -I PREROUTING $(( rule_idx++ )) -i ${LAN_DEV} -j MARK --set-mark ${TUN_MARK}
rule_idx="1"
ip6tables -t nat -I PREROUTING $(( rule_idx++ )) -p udp --dport 53 -m mark --mark ${DNS_MARK} -j REDIRECT --to-ports ${DNS_PORT}
