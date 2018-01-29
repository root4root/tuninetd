#!/bin/bash

#This is just example of how executable script, which run from tuninetd, may looks like.
#Accepts 'start' or 'stop' parameter.
#Author: root4root@gmail.com

controlFile='/var/run/ssh-myvpn-tunnel-control'
remoteHost='1.2.3.4'

function up()
{
    if [ ! -S $controlFile ]
    then
        /usr/bin/ssh -S $controlFile -M -f -w 0:0 $remoteHost ifconfig tun0 10.10.10.1/30 pointopoint 10.10.10.2
        exit 0
    else
        echo 'Tunnel already up!'
        exit 1
    fi
}

function down()
{
    if [ -S $controlFile ]
    then
        /usr/bin/ssh -S $controlFile -O exit $remoteHost
        exit 0
    else
        echo 'Tunnel already down!'
        exit 1
    fi
}

case $1 in
'start')
    up
    ;;
'stop' )
    down
    ;;
*)
    echo 'Usage: start|stop'
    ;;
esac

exit 1
