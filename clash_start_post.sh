#!/bin/bash

sleep 3

ip route replace default dev utun table 101
ip -6 route replace default dev utun table 101
ip rule add fwmark 0x02 table 101
ip -6 rule add fwmark 0x02 table 101
