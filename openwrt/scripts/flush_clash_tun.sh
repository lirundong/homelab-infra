#!/bin/bash
#
# Copy to /etc/flush_clash_tun.user
if [ ${EUID} -ne 0 ]; then
  echo "Please run as root"
  exit -1
fi

# Flush IPv6 rules.
ip6tables -t nat -F PREROUTING
ip6tables -t mangle -F PREROUTING
ip6tables -t filter -F forwarding_rule
ip6tables -t filter -F output_rule
ip6tables -t filter -F input_rule
ipset destroy local_ipv6

# Flush IPv4 rules.
iptables -t nat -F prerouting_rule
iptables -t mangle -F PREROUTING
iptables -t filter -F forwarding_rule
iptables -t filter -F output_rule
iptables -t filter -F input_rule
ipset destroy local_ipv4
