#!/bin/sh

uci -q batch << EOI
    set dhcp.@dnsmasq[0].local='/rundong.local/'
    set dhcp.@dnsmasq[0].domain='rundong.local'
    set dhcp.lan.interface='lan'
    set dhcp.lan.start='50'
    set dhcp.lan.limit='150'
    set dhcp.lan.leasetime='12h'
    set dhcp.lan.dhcpv4='server'
    set dhcp.lan.dhcpv6='disabled'
    set dhcp.lan.ra='server'
    set dhcp.lan.ra_slaac='1'
    delete dhcp.lan.ra_flags
    add_list dhcp.lan.ra_flags='managed-config'
    add_list dhcp.lan.ra_flags='other-config'
    set dhcp.odhcpd.maindhcp='0'

    commit dhcp
EOI
