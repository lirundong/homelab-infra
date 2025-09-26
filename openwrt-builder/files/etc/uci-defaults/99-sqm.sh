#!/bin/sh

if ! uci show sqm >/dev/null 2>&1; then
    uci import sqm < /dev/null
    uci commit sqm
fi

uci -q batch << EOI
    set sqm.eth1=queue
    set sqm.eth1.interface='eth1'
    set sqm.eth1.qdisc='cake'
    set sqm.eth1.script='layer_cake.qos'
    set sqm.eth1.debug_logging='0'
    set sqm.eth1.verbosity='5'
    set sqm.eth1.linklayer='ethernet'
    set sqm.eth1.overhead='44'
    set sqm.eth1.enabled='1'
    set sqm.eth1.download='350000'
    set sqm.eth1.upload='45000'

    commit sqm
EOI
