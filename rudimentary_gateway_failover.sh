#!/bin/bash

# Primary and failover gateway
# Failover gateway should either not have DHCP enabled or have an identical static lease assigned to this device
PRIMARY_GATEWAY=
FAILOVER_GATEWAY=

# If failover gateway is active as default,
RETRY_AFTER_SECONDS=60
# attempt a request through primary gateway after this timestamp
RETRY_AFTER=$(($(date +%s) + $RETRY_AFTER_SECONDS))
FAILOVER_SINCE=$(date +%s)

# Ethernet interface to which a gateway is applied
ETH_IF=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^eth|^en' | head -n1)

echo "*** $(date +"[%Y-%m-%d %H:%M:%S]") Providing automatic failover for ethernet interface $ETH_IF with primary gateway=$PRIMARY_GATEWAY, failover gateway=$FAILOVER_GATEWAY"

determineActiveGateway(){
	ACTIVE_GATEWAY=$(ip route show default | head -n1 | awk -F 'via ' '{print $2}' | awk -F 'dev $ETH_IF' '{print $1}' | cut -d ' ' -f1)
}

switchGateway(){
	if [ $ACTIVE_GATEWAY == $PRIMARY_GATEWAY  ]; then
		echo "*** $(date +"[%Y-%m-%d %H:%M:%S]") Switching gateway to $FAILOVER_GATEWAY"

		ip route change default via $FAILOVER_GATEWAY dev $ETH_IF proto static
		FAILOVER_SINCE=$(date +%s)
		RETRY_AFTER=$(($(date +%s) + $RETRY_AFTER_SECONDS))
	elif [ $ACTIVE_GATEWAY == $FAILOVER_GATEWAY ]; then
		echo "*** $(date +"[%Y-%m-%d %H:%M:%S]") Switching gateway to $PRIMARY_GATEWAY"
		ip route change default via $PRIMARY_GATEWAY dev $ETH_IF proto static
	else
		echo "*** $(date +"[%Y-%m-%d %H:%M:%S]") Error: unable to switch gateway, unexpected active gateway: $ACTIVE_GATEWAY"
		# ..
	fi

	reinitWireGuard
}

reinitWireGuard(){
	echo "*** $(date +"[%Y-%m-%d %H:%M:%S]") Reinitializing wg0"
	wg-quick down wg0
	wg-quick up wg0
}

performRequest(){
	curl --connect-timeout 2 --retry 2 --retry-delay 1 --max-time 5 --retry-max-time 2 google.com &> /dev/null
}


while true
do
	determineActiveGateway

	echo "*** $(date +"[%Y-%m-%d %H:%M:%S]") Active gateway=$ACTIVE_GATEWAY"

	# If google is down..
	# Also ensures proper DNS resolving
	performRequest
	RES=$?

	if [ $RES -eq 0  ]; then
		echo "*** $(date +"[%Y-%m-%d %H:%M:%S]") Request OK"

		if [ $ACTIVE_GATEWAY == $FAILOVER_GATEWAY  ]; then
			NOW=$(date +%s)

			if [ $NOW -gt $RETRY_AFTER ]; then
				echo "*** $(date +"[%Y-%m-%d %H:%M:%S]") Failover active for >$RETRY_AFTER_SECONDS seconds, retrying primary gateway again.."

				# Attempt comms through primary gateway
				switchGateway
				performRequest

				if [ $RES -gt 0  ]; then
					# If it failed, switch back to the failover gateway
					switchGateway
				fi
			else
				echo "*** $(date +"[%Y-%m-%d %H:%M:%S]") Keeping failover gateway active, active since ts=$FAILOVER_SINCE"
			fi
		fi
	else
		echo "*** $(date +"[%Y-%m-%d %H:%M:%S]") Request failed"
		switchGateway
	fi

	echo ""

	sleep 1
done

