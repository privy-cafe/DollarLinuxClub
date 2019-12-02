#! /bin/sh
#ulimit -n 100000
#ulimit -a

sysctl -w net.core.rmem_max=12582912
sysctl -w net.core.wmem_max=12582912
sysctl -w net.core.rmem_default=65536
sysctl -w net.core.wmem_default=65536
sysctl -w net.ipv4.tcp_rmem='4096 87380 12582912'
sysctl -w net.ipv4.tcp_wmem='4096 87380 12582912'
sysctl -w net.ipv4.tcp_mem='8388608 8388608 8388608'
sysctl -w net.ipv4.tcp_mem='8388608 8388608 8388608'
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.tcp_window_scaling=1
sysctl -w net.ipv4.tcp_congestion_control=bbr
sysctl -w net.core.somaxconn=510
sysctl -w net.core.netdev_max_backlog=2000
sysctl -w net.ipv4.ip_local_port_range='1024 65000'
sysctl -p
