#!/bin/sh

uci -q batch << EOI
    set dropbear.@dropbear[0].Port='22'
    set dropbear.@dropbear[0].Interface='lan'
    set dropbear.@dropbear[0].PasswordAuth='off'

    commit dropbear
EOI
