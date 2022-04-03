#!/bin/sh

# Delete existing devices.
while uci -q delete network.@device[0]; do :; done
uci commit

uci -q batch << EOI
    # Setup bridge.
    add network device
    set network.@device[0].name='br-lan'
    set network.@device[0].type='bridge'
    delete network.@device[0].ports
    add_list network.@device[0].ports='eth0'
    add_list network.@device[0].ports='eth2'

    # Setup LAN.
    delete network.lan
    set network.lan=interface
    set network.lan.device='br-lan'
    set network.lan.proto='static'
    set network.lan.ipaddr='192.168.50.1'
    set network.lan.netmask='255.255.255.0'
    set network.lan.ip6assign='64'

    # Setup WAN.
    delete network.wan
    set network.wan=interface
    set network.wan.device='eth1'
    set network.wan.proto='pppoe'
    set network.wan.username='@secret:PPPOE_USERNAME'
    set network.wan.password='@secret:PPPOE_PASSWORD'
    set network.wan.ipv6='auto'

    commit network
EOI
