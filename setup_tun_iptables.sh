#!/bin/bash
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
LOCAL_IPSET="localnetwork"
TUN_DEV="utun0"
TUN_TABLE="101" # 100 was for TProxy routes.
TUN_MARK="0x02"

# 1. Create local IP addresses set.
ipset create ${LOCAL_IPSET} hash:net
for LOCAL_IP in ${LOCAL_IPS[@]}; do
  ipset add ${LOCAL_IPSET} ${LOCAL_IP}
done
# 2. Bringup TUN device.
ip tuntap add user root mode tun ${TUN_DEV}
ip link set ${TUN_DEV} up
# 3. Setup iptables to mark traffic that requires filtering.
iptables -t mangle -N CLASH
iptables -t mangle -F CLASH
iptables -t mangle -A CLASH -p tcp --dport 53 -j MARK --set-mark ${TUN_MARK}
iptables -t mangle -A CLASH -p udp --dport 53 -j MARK --set-mark ${TUN_MARK}
iptables -t mangle -A CLASH -m addrtype --dst-type BROADCAST -j RETURN
for LOCAL_IP in ${LOCAL_IPS[@]}; do
  iptables -t mangle -A CLASH -d ${LOCAL_IP} -j RETURN
done
iptables -t mangle -A CLASH -j MARK --set-mark ${TUN_MARK}

iptables -t mangle -I OUTPUT -j CLASH
iptables -t mangle -I PREROUTING -m set ! --match-set ${LOCAL_IPSET} dst -j MARK --set-mark ${TUN_MARK}
# 4. Setup ip rules to route marked traffic to the TUN device.
ip route add default dev ${TUN_DEV} table ${TUN_TABLE}
ip rule add fwmark ${TUN_MARK} table ${TUN_TABLE}