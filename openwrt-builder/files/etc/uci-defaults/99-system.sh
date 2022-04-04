#!/bin/sh

uci -q batch << EOI
    set system.@system[0].hostname='router'
    set system.@system[0].zonename='Asia/Shanghai'
    set system.@system[0].timezone='CST-8'

    commit system
EOI
