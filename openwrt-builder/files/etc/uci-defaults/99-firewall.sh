#!/bin/sh

# ==============================================================================
#   Zone rules.
# ==============================================================================
# Create a zone for sing-box tunnels and enable approperate forwardings.
zone_id=$(uci add firewall zone)
uci set firewall.$zone_id.name='sing-box'
uci set firewall.$zone_id.device='tun+'
uci set firewall.$zone_id.input='ACCEPT'
uci set firewall.$zone_id.output='ACCEPT'
uci set firewall.$zone_id.forward='REJECT'

forwarding_id=$(uci add firewall forwarding)
uci set firewall.$forwarding_id.src='sing-box'
uci set firewall.$forwarding_id.dest='lan'

forwarding_id=$(uci add firewall forwarding)
uci set firewall.$forwarding_id.src='lan'
uci set firewall.$forwarding_id.dest='sing-box'

# ==============================================================================
#   Input rules.
# ==============================================================================
# Allow KMS inputs from WAN.
rule_id=$(uci add firewall rule)
uci set firewall.$rule_id.name='Allow-KMS-WAN'
uci set firewall.$rule_id.src='wan'
uci set firewall.$rule_id.dest_port='1688'
uci add_list firewall.$rule_id.proto='tcp'
uci add_list firewall.$rule_id.proto='udp'
uci set firewall.$rule_id.target='ACCEPT'

# ==============================================================================
#   IPv4 forward rules.
# ==============================================================================
# Forward synonas web services.
rule_id=$(uci add firewall redirect)
uci set firewall.$rule_id.name='DNAT-services@synonas-WAN-LAN'
uci set firewall.$rule_id.src='wan'
uci set firewall.$rule_id.src_dport='5000:5009'
uci set firewall.$rule_id.dest='lan'
uci set firewall.$rule_id.dest_ip='192.168.50.6'
uci set firewall.$rule_id.dest_port='5000:5009'
uci add_list firewall.$rule_id.proto='tcp'
uci add_list firewall.$rule_id.proto='udp'
uci set firewall.$rule_id.family='ipv4'
uci set firewall.$rule_id.target='DNAT'

# Forward truenas web services.
rule_id=$(uci add firewall redirect)
uci set firewall.$rule_id.name='DNAT-services@truenas-WAN-LAN'
uci set firewall.$rule_id.src='wan'
uci set firewall.$rule_id.src_dport='5010:5019'
uci set firewall.$rule_id.dest='lan'
uci set firewall.$rule_id.dest_ip='192.168.50.5'
uci set firewall.$rule_id.dest_port='5010:5019'
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

# Forward truenas qBittorrent.
rule_id=$(uci add firewall redirect)
uci set firewall.$rule_id.name='DNAT-qBitTorrent@truenas-WAN-LAN'
uci set firewall.$rule_id.src='wan'
uci set firewall.$rule_id.src_dport='11082:11083'
uci set firewall.$rule_id.dest='lan'
uci set firewall.$rule_id.dest_ip='192.168.50.5'
uci set firewall.$rule_id.dest_port='11082:11083'
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

# Forward plex-gpu.
rule_id=$(uci add firewall redirect)
uci set firewall.$rule_id.name='DNAT-Plex@plex-gpu-WAN-LAN'
uci set firewall.$rule_id.src='wan'
uci set firewall.$rule_id.src_dport='32400'
uci set firewall.$rule_id.dest='lan'
uci set firewall.$rule_id.dest_ip='192.168.50.10'
uci set firewall.$rule_id.dest_port='32400'
uci add_list firewall.$rule_id.proto='tcp'
uci add_list firewall.$rule_id.proto='udp'
uci set firewall.$rule_id.family='ipv4'
uci set firewall.$rule_id.target='DNAT'

# ==============================================================================
#   IPv6 forward rules.
# ==============================================================================
# Allow web services forwarding from WAN to {synonas, truenas} via IPv6.
rule_id=$(uci add firewall rule)
uci set firewall.$rule_id.name='Allow-web-services-WAN-LAN'
uci set firewall.$rule_id.src='wan'
uci set firewall.$rule_id.dest='lan'
uci set firewall.$rule_id.dest_port='5000:5019'
uci add_list firewall.$rule_id.proto='tcp'
uci add_list firewall.$rule_id.proto='udp'
uci set firewall.$rule_id.family='ipv6'
uci set firewall.$rule_id.target='ACCEPT'

# Allow qBittorrent forwarding from WAN to {synonas, truenas} via IPv6.
rule_id=$(uci add firewall rule)
uci set firewall.$rule_id.name='Allow-qBitTorrent-WAN-LAN'
uci set firewall.$rule_id.src='wan'
uci set firewall.$rule_id.dest='lan'
uci set firewall.$rule_id.dest_port='11080:11083'
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

# Allow Plex forward from WAN to plex-gpu via IPv6.
rule_id=$(uci add firewall rule)
uci set firewall.$rule_id.name='Allow-Plex@plex-gpu-WAN-LAN'
uci set firewall.$rule_id.src='wan'
uci set firewall.$rule_id.dest='lan'
uci set firewall.$rule_id.dest_port='32400'
uci add_list firewall.$rule_id.proto='tcp'
uci add_list firewall.$rule_id.proto='udp'
uci set firewall.$rule_id.family='ipv6'
uci set firewall.$rule_id.target='ACCEPT'

uci commit firewall
