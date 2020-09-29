#!/bin/bash
set -xe

LOCAL_IPV4="192.168.50.2"
REDIR_PORT="10082"
DNS_PORT="10053"

ipset create localnetwork hash:net
ipset add localnetwork 127.0.0.0/8
ipset add localnetwork 10.0.0.0/8
ipset add localnetwork 169.254.0.0/16
ipset add localnetwork 192.168.0.0/16
ipset add localnetwork 224.0.0.0/4
ipset add localnetwork 240.0.0.0/4
ipset add localnetwork 172.16.0.0/12
ip tuntap add user root mode tun utun0
ip link set utun0 up
ip address replace 172.31.255.253/30 dev utun0
ip route replace default dev utun0 table 0x162
ip rule add fwmark 0x162 lookup 0x162
iptables -t mangle -N CLASH
iptables -t mangle -F CLASH
iptables -t mangle -A CLASH -d 198.18.0.0/16 -j MARK --set-mark 0x162
iptables -t mangle -A CLASH -m addrtype --dst-type BROADCAST -j RETURN
iptables -t mangle -A CLASH -m set --match-set localnetwork dst -j RETURN
iptables -t mangle -A CLASH -j MARK --set-mark 0x162
iptables -t nat -N CLASH_DNS
iptables -t nat -F CLASH_DNS 
iptables -t nat -A CLASH_DNS -p udp -j REDIRECT --to-port "$DNS_PORT"
iptables -t mangle -I OUTPUT -j CLASH
iptables -t mangle -I PREROUTING -m set ! --match-set localnetwork dst -j MARK --set-mark 0x162
iptables -t nat -I OUTPUT -p udp --dport 53 -j CLASH_DNS
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to "$DNS_PORT"
iptables -t filter -I OUTPUT -d 172.31.255.253/30 -j REJECT