#!/bin/bash

iptables -D FORWARD -s $1 -j ACCEPT
iptables -t nat -D PREROUTING -s $1 -j ACCEPT


