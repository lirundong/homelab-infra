#!/bin/bash
set -xe

LOCAL_IPV4="192.168.50.2"
REDIR_PORT="10082"
DNS_PORT="10053"

# TCP
iptables -t nat -N CLASH
iptables -t nat -A CLASH -d 0.0.0.0/8 -j RETURN
iptables -t nat -A CLASH -d 10.0.0.0/8 -j RETURN
iptables -t nat -A CLASH -d 127.0.0.0/8 -j RETURN
iptables -t nat -A CLASH -d 169.254.0.0/16 -j RETURN
iptables -t nat -A CLASH -d 172.16.0.0/12 -j RETURN
iptables -t nat -A CLASH -d 192.168.0.0/16 -j RETURN
iptables -t nat -A CLASH -d 224.0.0.0/4 -j RETURN
iptables -t nat -A CLASH -d 240.0.0.0/4 -j RETURN
iptables -t nat -A CLASH -d "$LOCAL_IPV4" -j RETURN
iptables -t nat -A CLASH -p tcp -j REDIRECT --to-port "$REDIR_PORT"
iptables -t nat -I PREROUTING -p tcp -d 8.8.8.8 -j REDIRECT --to-port "$REDIR_PORT"
iptables -t nat -I PREROUTING -p tcp -d 8.8.4.4 -j REDIRECT --to-port "$REDIR_PORT"
iptables -t nat -A PREROUTING -p tcp -j CLASH

# UDP
ip rule add fwmark 1 table 100
ip route add local default dev lo table 100
iptables -t mangle -N CLASH
iptables -t mangle -A CLASH -d 0.0.0.0/8 -j RETURN
iptables -t mangle -A CLASH -d 10.0.0.0/8 -j RETURN
iptables -t mangle -A CLASH -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A CLASH -d 169.254.0.0/16 -j RETURN
iptables -t mangle -A CLASH -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A CLASH -d 192.168.0.0/16 -j RETURN
iptables -t mangle -A CLASH -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A CLASH -d 240.0.0.0/4 -j RETURN
iptables -t mangle -A CLASH -d "$LOCAL_IPV4" -j RETURN
iptables -t mangle -A CLASH -p udp -j TPROXY --on-port "$REDIR_PORT" --tproxy-mark 1
iptables -t mangle -A PREROUTING -p udp -j CLASH

# DNS
iptables -t nat -N CLASH_DNS
iptables -t nat -F CLASH_DNS 
iptables -t nat -A CLASH_DNS -p udp -j REDIRECT --to-port "$DNS_PORT"
iptables -t nat -I OUTPUT -p udp --dport 53 -j CLASH_DNS
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to "$DNS_PORT"