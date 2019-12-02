#!/bin/sh

IF=$1
STATUS=$2
MACCHANGER=/usr/bin/macchanger
WLANIFACE="wlan0"

if [ -z "$IF" ]; then
echo "$0: called with no interface" 1>&2
exit 1;
fi
if [ ! -x $MACCHANGER ]; then
echo "$0: can’t call $MACCHANGER" 1>&2
exit 1;
fi

if [ "$IF" = "$WLANIFACE" ] && [ "$STATUS" = "down" ]; then
/usr/sbin/ip link set $IF down
$MACCHANGER -r $IF
/usr/sbin/ip link set $IF up
fi 
