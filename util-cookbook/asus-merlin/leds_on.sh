#!/bin/sh

nvram set led_disable=0
service restart_leds
