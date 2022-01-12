#!/bin/bash
#
# Copy to /etc/setup_clash_tun.user
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
INTERFACE_IP6S=( $(ifconfig | grep 'inet6 addr' | awk '{print $3}' 2>/dev/null) )
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
  "${INTERFACE_IP6S[@]}"
)
DIRECT_MACS=(
  "00:11:32:ac:77:2e" # synonas eth0
  "64:ff:0a:4b:8c:c1" # Sony-TV WiFi
  "70:85:c2:da:43:f4" # Rundong-Gaming-PC, Intel I219-V interface.
  "00:e4:21:6a:eb:a3" # PS5
)
TPROXY_MARK="0x01"
TUN_MARK="0x02"
DNS_MARK="0x03"
DNS_PORT="10053"
SOCKS_PORT="10080"
HTTP_PORT="10081"
TPROXY_PORT="10083"
LAN_DEV="br-lan"
TUN_DEV="utun"

# Prepare ipsets that contan local IP addresses and MAC address.
local_mac="local_mac"
ipset create ${local_mac} hash:mac >/dev/null 2>&1
for MAC in ${DIRECT_MACS[@]}; do
  ipset add ${local_mac} ${MAC}
done
local_ipv4="local_ipv4"
ipset create ${local_ipv4} hash:net >/dev/null 2>&1
for LOCAL_IP in ${LOCAL_IPS[@]}; do
  ipset add ${local_ipv4} ${LOCAL_IP}
done
local_ipv6="local_ipv6"
ipset create ${local_ipv6} hash:net family inet6 >/dev/null 2>&1
for LOCAL_IP6 in ${LOCAL_IP6S[@]}; do
  ipset add ${local_ipv6} ${LOCAL_IP6} 2>/dev/null # Supress duplicate error.
done

# IPv4 config.
# Filter table. Note that we inset to fw3 custom chains to make flush easier.
#
# 1. Accept TUN inputs and outputs.
iptables -t filter -A input_rule -i ${TUN_DEV} -j ACCEPT
iptables -t filter -A output_rule -o ${TUN_DEV} -j ACCEPT
# 2. Accept br-lan <-> TUN firwarding.
iptables -t filter -A forwarding_rule -i ${LAN_DEV} -o ${TUN_DEV} -m conntrack --ctstate INVALID -j DROP
iptables -t filter -A forwarding_rule -i ${LAN_DEV} -o ${TUN_DEV} -j ACCEPT
iptables -t filter -A forwarding_rule -i ${TUN_DEV} -o ${LAN_DEV} -j ACCEPT
# Mangle table.
#
# 1. Do not touch direct-to-wan packets.
iptables -t mangle -A PREROUTING -i ${LAN_DEV} -m set --match-set ${local_mac} src -j RETURN 
# 2. Mark and accept DNS packets, they will be redirted to Clash DNS port by NAT rules later.
iptables -t mangle -A PREROUTING -p udp --dport 53 -j MARK --set-mark ${DNS_MARK}
iptables -t mangle -A PREROUTING -p udp --dport 53 -j RETURN
# 3. Bypass local connectons.
iptables -t mangle -A PREROUTING -m set --match-set ${local_ipv4} dst -j RETURN
# 4. Mark all remaining packets and route them to TUN later.
iptables -t mangle -A PREROUTING -i ${LAN_DEV} -j MARK --set-mark ${TUN_MARK}
# NAT table.
#
# 1. Finally, take care of DNS packets.
iptables -t nat -A prerouting_rule -p udp --dport 53 -m mark --mark ${DNS_MARK} -j REDIRECT --to-ports ${DNS_PORT}

# IPv6 config. It is handled by TProxy, as TUN does not accept inbound traffic currently:
#   https://github.com/Dreamacro/clash/issues/1461#issuecomment-869404975
# Accept TUN input, output and forward.
ip6tables -t filter -A input_rule -i ${TUN_DEV} -j ACCEPT
ip6tables -t filter -A output_rule -o ${TUN_DEV} -j ACCEPT
ip6tables -t filter -A forwarding_rule -i ${LAN_DEV} -o ${TUN_DEV} -m conntrack --ctstate INVALID -j DROP
ip6tables -t filter -A forwarding_rule -i ${LAN_DEV} -o ${TUN_DEV} -j ACCEPT
ip6tables -t filter -A forwarding_rule -i ${TUN_DEV} -o ${LAN_DEV} -j ACCEPT
# Mangle table rules.
ip6tables -t mangle -A PREROUTING -i ${LAN_DEV} -m set --match-set ${local_mac} src -j RETURN 
ip6tables -t mangle -A PREROUTING -p udp --dport 53 -j MARK --set-mark ${DNS_MARK}
ip6tables -t mangle -A PREROUTING -p udp --dport 53 -j RETURN
ip6tables -t mangle -A PREROUTING -m set --match-set ${local_ipv6} dst -j RETURN
ip6tables -t mangle -A PREROUTING -i ${LAN_DEV} -p tcp -j TPROXY --on-port ${TPROXY_PORT} --tproxy-mark ${TPROXY_MARK}
ip6tables -t mangle -A PREROUTING -i ${LAN_DEV} -p udp -j TPROXY --on-port ${TPROXY_PORT} --tproxy-mark ${TPROXY_MARK}
# Handle DNS packets.
ip6tables -t nat -A PREROUTING -p udp --dport 53 -m mark --mark ${DNS_MARK} -j REDIRECT --to-ports ${DNS_PORT}
