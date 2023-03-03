#!/bin/sh

# Allow KMS inputs from WAN.
rule_id=$(uci add firewall rule)
uci set firewall.$rule_id.name='Allow-KMS-WAN'
uci set firewall.$rule_id.src='wan'
uci set firewall.$rule_id.dest_port='1688'
uci add_list firewall.$rule_id.proto='tcp'
uci add_list firewall.$rule_id.proto='udp'
uci set firewall.$rule_id.target='ACCEPT'

# Allow qBittorrent forwarding from WAN to synonas via IPv6.
rule_id=$(uci add firewall rule)
uci set firewall.$rule_id.name='Allow-qBitTorrent-WAN-LAN'
uci set firewall.$rule_id.src='wan'
uci set firewall.$rule_id.dest='lan'
uci set firewall.$rule_id.dest_port='11080:11081'
uci add_list firewall.$rule_id.proto='tcp'
uci add_list firewall.$rule_id.proto='udp'
uci set firewall.$rule_id.family='ipv6'
uci set firewall.$rule_id.target='ACCEPT'

# Allow SSH forward from WAN to synonas via IPv6.
rule_id=$(uci add firewall rule)
uci set firewall.$rule_id.name='Allow-SSH@synonas-WAN-LAN'
uci set firewall.$rule_id.src='wan'
uci set firewall.$rule_id.dest='lan'
uci set firewall.$rule_id.dest_port='28996'
uci set firewall.$rule_id.proto='tcp'
uci set firewall.$rule_id.family='ipv6'
uci set firewall.$rule_id.target='ACCEPT'

# Allow Plex forward from WAN to synonas via IPv6.
rule_id=$(uci add firewall rule)
uci set firewall.$rule_id.name='Allow-Plex@synonas-WAN-LAN'
uci set firewall.$rule_id.src='wan'
uci set firewall.$rule_id.dest='lan'
uci set firewall.$rule_id.dest_port='32400'
uci add_list firewall.$rule_id.proto='tcp'
uci add_list firewall.$rule_id.proto='udp'
uci set firewall.$rule_id.family='ipv6'
uci set firewall.$rule_id.target='ACCEPT'

# Forward synonas web services.
rule_id=$(uci add firewall redirect)
uci set firewall.$rule_id.name='DNAT-services@synonas-WAN-LAN'
uci set firewall.$rule_id.src='wan'
uci set firewall.$rule_id.src_dport='5000:5010'
uci set firewall.$rule_id.dest='lan'
uci set firewall.$rule_id.dest_ip='192.168.50.6'
uci set firewall.$rule_id.dest_port='5000:5010'
uci add_list firewall.$rule_id.proto='tcp'
uci add_list firewall.$rule_id.proto='udp'
uci set firewall.$rule_id.family='ipv4'
uci set firewall.$rule_id.target='DNAT'

# Forward synonas qBittorrent.
rule_id=$(uci add firewall redirect)
uci set firewall.$rule_id.name='DNAT-qBitTorrent@synonas-WAN-LAN'
uci set firewall.$rule_id.src='wan'
uci set firewall.$rule_id.src_dport='11080:11081'
uci set firewall.$rule_id.dest='lan'
uci set firewall.$rule_id.dest_ip='192.168.50.6'
uci set firewall.$rule_id.dest_port='11080:11081'
uci add_list firewall.$rule_id.proto='tcp'
uci add_list firewall.$rule_id.proto='udp'
uci set firewall.$rule_id.family='ipv4'
uci set firewall.$rule_id.target='DNAT'

# Forward synonas SSH.
rule_id=$(uci add firewall redirect)
uci set firewall.$rule_id.name='DNAT-SSH@synonas-WAN-LAN'
uci set firewall.$rule_id.src='wan'
uci set firewall.$rule_id.src_dport='28996'
uci set firewall.$rule_id.dest='lan'
uci set firewall.$rule_id.dest_ip='192.168.50.6'
uci set firewall.$rule_id.dest_port='28996'
uci set firewall.$rule_id.proto='tcp'
uci set firewall.$rule_id.family='ipv4'
uci set firewall.$rule_id.target='DNAT'

# Forward synonas Plex.
rule_id=$(uci add firewall redirect)
uci set firewall.$rule_id.name='DNAT-Plex@synonas-WAN-LAN'
uci set firewall.$rule_id.src='wan'
uci set firewall.$rule_id.src_dport='32400'
uci set firewall.$rule_id.dest='lan'
uci set firewall.$rule_id.dest_ip='192.168.50.6'
uci set firewall.$rule_id.dest_port='32400'
uci add_list firewall.$rule_id.proto='tcp'
uci add_list firewall.$rule_id.proto='udp'
uci set firewall.$rule_id.family='ipv4'
uci set firewall.$rule_id.target='DNAT'

uci commit firewall
