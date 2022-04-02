#!/bin/sh

nvram set led_disable=1
service restart_leds
