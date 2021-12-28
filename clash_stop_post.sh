#!/bin/bash

ip route flush table 101
ip -6 route flush table 101
ip rule delete fwmark 0x02 table 101
ip -6 rule delete fwmark 0x02 table 101
