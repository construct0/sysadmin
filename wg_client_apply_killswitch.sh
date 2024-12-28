#!/bin/bash
set -x 

# Example killswitch, requires iptables-persistent, netfilter-persistent, ipcalc
# and wireguard client to be configured at /etc/wireguard/wg0.conf

# Allow traffic through wireguard interface
# Requires wireguard client with interface wg0 to exist
iptables -A OUTPUT -o wg0 -j ACCEPT
iptables -A INPUT -i wg0 -j ACCEPT

# Allow local device traffic between services
iptables -A INPUT -s localhost -j ACCEPT
iptables -A OUTPUT -d localhost -j ACCEPT

# Allow local network traffic
LAN_SUBNET=$(ip -o -f inet addr show $(ip -o link show | awk -F': ' '{print $2}' | grep -E '^eth|^en' | head -n 1) | awk '{print $4}' | awk -F'/' '{system("ipcalc -n "$1" "$2)}' | awk '/Network:/ {print $2}')
iptables -A INPUT -s $LAN_SUBNET -j ACCEPT
iptables -A OUTPUT -d $LAN_SUBNET -j ACCEPT

# Allow traffic to the wireguard server
WG_SERVER_IP=$(cat /etc/wireguard/wg0.conf | grep "Endpoint" | cut -d '=' -f2 | cut -d ':' -f1 | sed 's/[[:space:]]//g')
WG_SERVER_PORT=$(cat /etc/wireguard/wg0.conf | grep "Endpoint" | cut -d '=' -f2 | cut -d ':' -f2 | sed 's/[[:space:]]//g')
iptables -A OUTPUT -d $WG_SERVER_IP -p udp --dport $WG_SERVER_PORT -j ACCEPT

# Drop other outbound traffic
iptables -A OUTPUT ! -o wg0 -j DROP

# Persist the killswitch rules
netfilter-persistent save

# Shows the iptables rules
# iptables --list
