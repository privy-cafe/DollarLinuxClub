#!/bin/bash
declare -i PERCENT=0
(
if [ -f /lib/live/mount/medium/md5sum.txt ];then
    num=0
    while read line
    do
	if [ $PERCENT -le 100 ];then
	    echo "XXX"
	    echo "check ${line##* }..."
	    echo "XXX"
	    md5=`md5sum /lib/live/mount/medium/${line##* }`
	    if [ "${md5%% *}" != "${line%% *}" ];then
		echo "XXX"
		echo "check ${line##* } error!" >/tmp/check_failed
		echo "XXX"
		break
	    fi
	    echo $PERCENT
	fi
	let num+=1
	if [ "$num" == "5" ];then
	    let PERCENT+=1;
	    num=0
	fi
    done < /lib/live/mount/medium/md5sum.txt
fi
) | dialog --title "check md5..." --gauge "starting to check md5..." 6 100 0
if [ -f /tmp/check_failed ];then
    value=`cat /tmp/check_failed`
    dialog --title "check md5" --msgbox "checksum failed \n  $value "  10 60
else
    dialog --title "check md5" --msgbox "checksum success"  10 20
fi
echo 1 > /proc/sys/kernel/sysrq
echo b > /proc/sysrq-trigger
