#!/bin/sh

###############################################################################
# Firewall rules to my personal laptop.
#
# A firewall script intended to be used on workstations/laptops. It basically
# blocks most & opens only what is minimally required.
#
# Detailed description of this is available on my blog:
#	http://tech.meetrp.com/blog/iptables-personal-firewall-to-protect-my-laptop/
#
# Note: Work in progress. Any suggestions are welcome. :)
#
# Courtesy:
#	* http://linux-sxs.org/security/hunleyfw.html
#	* http://kernel-project.kickino.org/index_moz_en.php?action=security
#	* http://youtu.be/D7LgjSOWCxg
#	* http://terraltech.com/saving-iptables-rules-to-be-persistent/
#	* http://hermann-uwe.de/files/fw_laptop
###############################################################################


# Absolute paths for helper scripts/commands
AWK=`which awk`
ECHO=`which echo`
GREP=`which grep`
IFCONFIG=`which ifconfig`
IPv4TABLES=`which iptables`
IPv6TABLES=`which ip6tables`
LS=`which ls`
SUDO=`which sudo`

# Required paths
ROOT_DIR="/root"


###############################################################################
# Set the file to zero
##
log() {
	if [ $# -gt 0 ]; then
		now=`date "+%x %T"`
		$ECHO -e "[$now] $1"
	else
		$ECHO
	fi
}


###############################################################################
# Set the file to zero
##
disable() {
	for file in $@
	do
		$SUDO $ECHO 0 > $file
	done
}

###############################################################################
# Set the file to one
##
enable() {
	for file in $@
	do
		$SUDO $ECHO 1 > $file
	done
}


###############################################################################
# Ignore the broadcast pings
#
# This deals only with IPv4 ICMP 'echo' broadcasts. ICMP echo messages are
# the messages used by the "ping" command-line tool. By ignoring broadcast
# ICMP echo requests, your machine won't respond when someone tries to
# ping a broadcast address (such as 255.255.255.255, or, say, 192.168.1.255
# on a 192.168.1.0/24 subnet) to find all the hosts on the network or
# subnet at the same time.
##
enable_broadcast_echo_protection() {
	if [ -e /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts ]; then
		log "{IGNORE} \t\t ICMP echo broadcasts"
		enable /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
	fi
}


###############################################################################
# Deactivate source routed packets
#
# Attackers could be using source-routed packets to generate traffic that seems
# to be intra-net, but actually was created outside and has been redirected.
##
disable_source_routed_packets() {
	if [ -e /proc/sys/net/ipv4/conf/all/accept_source_route ]; then
		log "{DISABLE} \t\t source route"
		for iter in /proc/sys/net/ipv4/conf/*/accept_source_route
		do
			disable $iter
		done
	fi
}


###############################################################################
# Disable ICMP redirects
#
# ICMP redirects are used by routers to specify better routing paths out of one
# network, based on the host choice, so basically it affects the way packets
# are routed and destinations. The atacker can then on basically alter your
# host's routing tables and diver traffic towards external hosts on a path of
# his/her choice; the new path is kept active by the router for 10 minutes.
##
disable_icmp_redirects() {
	if [ -e /proc/sys/net/ipv4/conf/all/accept_redirects ]; then
		log "{DISABLE} \t\t ICMP redirects"
		for iter in /proc/sys/net/ipv4/conf/*/accept_redirects
		do
			disable $iter
		done
	fi
}


###############################################################################
# Disable IP forwarding
#
# If there are mulitple network interfaces (like eth0, eth1, wlan0) active at
# the same time, then traffic coming in from one interface can be forwarded
# to another interface. This feature is not required in a traditional laptop
##
disable_ip_forwarding() {
	if [ -e /proc/sys/net/ipv4/ip_forward ]; then
		log "{DISABLE} \t\t IP forwarding"
		disable /proc/sys/net/ipv4/ip_forward
	fi
}


###############################################################################
# turn on source address verfication
#
# By default, routers route everything, even packets which 'obviously' don't
# belong on your network. A common example is private IP space escaping onto the
# Internet. If you have an interface with a route of 195.96.96.0/24 to it, you
# do not expect packets from 212.64.94.1 to arrive there. Enabling this 
# verification implies if the reply to a packet wouldn't go out the interface
# this packet came in, then this is a bogus packet and should be ignored.
##
enable_source_address_verification() {
	if [ -e /proc/sys/net/ipv4/conf/all/rp_filter ]; then
		log "{ENABLE} \t\t reverse path filtering"
		for iter in /proc/sys/net/ipv4/conf/*/rp_filter
		do
			enable $iter
		done
	fi
}


###############################################################################
# turn on syn cookies protection
#
# The TCP Syn is DoS (Denial of Service) attack. It consumes resources on your
# Linux server. The attacker begin with the TCP connection handshake sending
# the SYN packet, and then never completing the process to open the connection.
# This results into massive half-open connections.
##
enable_tcp_syn_cookies() {
	if [ -e /proc/sys/net/ipv4/tcp_syncookies ]; then
		log "{ENABLE} \t\t SYN cookies protetion"
		enable /proc/sys/net/ipv4/tcp_syncookies
	fi
}


###############################################################################
# Drop all traffic from IANA-reserved IPs
#
# Note: You could easily block valid traffic, e.g. if your ISP uses private
# addresses (see RFC 1918) in their network. If in doubt, remove these rules.
# For details see:
#	* ftp://ftp.iana.org/assignments/ipv4-address-space
#	* http://www.cymru.com/Documents/bogon-bn-agg.txt
##
drop_IANA_reserved_ips() {
	iptables_bin=$1
	log "{DROP} INCOMING: \t\t\t all IANA reserved IPs"

	$SUDO ${iptables_bin} -A INPUT -s 0.0.0.0/7 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 2.0.0.0/8 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 5.0.0.0/8 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 7.0.0.0/8 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 10.0.0.0/8 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 23.0.0.0/8 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 27.0.0.0/8 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 31.0.0.0/8 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 36.0.0.0/7 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 39.0.0.0/8 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 42.0.0.0/8 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 49.0.0.0/8 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 50.0.0.0/8 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 77.0.0.0/8 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 78.0.0.0/7 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 92.0.0.0/6 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 96.0.0.0/4 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 112.0.0.0/5 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 120.0.0.0/8 -j DROP
	# $SUDO ${iptables_bin} -A INPUT -s 127.0.0.0/8 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 169.254.0.0/16 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 172.16.0.0/12 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 173.0.0.0/8 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 174.0.0.0/7 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 176.0.0.0/5 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 184.0.0.0/6 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 192.0.2.0/24 -j DROP
	# $SUDO ${iptables_bin} -A INPUT -s 192.168.0.0/16 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 197.0.0.0/8 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 198.18.0.0/15 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 223.0.0.0/8 -j DROP
	$SUDO ${iptables_bin} -A INPUT -s 224.0.0.0/3 -j DROP
}

###############################################################################
# Log spoofed, source-routed or redirected packets
#
# A Martian packet is nothing but an IP packet which specifies a source or
# destination address that is reserved for special-use by Internet Assigned
# Numbers Authority (IANA). Examples of address blocks:
#	10.0.0.0/8,
#	127.0.0.0/8
# 	224.0.0.0/4,
#	240.0.0.0/4,
#	::/128,
#	::/96,
#	::1/128
# This logs packets with un-routable source addresses to the kernel log file
# such as /var/log/messages.
##
enable_log_martians() {
	if [ -e /proc/sys/net/ipv4/conf/all/log_martians ]; then
		log "{ENABLE} \t\t log for all unroutable packets"
		for iter in /proc/sys/net/ipv4/conf/*/log_martians
		do
			enable $iter
		done
	fi
}


###############################################################################
# Enable/Disable appropriate functionality
##
disable_enable_kernel_features() {
	enable_broadcast_echo_protection
	enable_log_martians
	enable_source_address_verification
	enable_tcp_syn_cookies

	disable_icmp_redirects
	disable_ip_forwarding
	disable_source_routed_packets
}


###############################################################################
# Set the default policy for all the chains as DROP
##
clear_all_rules() {
	log "clear all rules"

	iptables_bin=$1

	# default table is filter
	$SUDO ${iptables_bin} -F -t filter
	$SUDO ${iptables_bin} -F -t nat
	$SUDO ${iptables_bin} -F -t mangle
}


###############################################################################
# Set the default policy for all the chains as DROP
##
default_drop_all() {
	log "default drop"

	iptables_bin=$1

	# filter table
	$SUDO ${iptables_bin} -t filter -P INPUT DROP
	$SUDO ${iptables_bin} -t filter -P OUTPUT DROP
	$SUDO ${iptables_bin} -t filter -P FORWARD DROP

	# mangle table
	$SUDO ${iptables_bin} -t mangle -P PREROUTING DROP
	$SUDO ${iptables_bin} -t mangle -P INPUT DROP
	$SUDO ${iptables_bin} -t mangle -P OUTPUT DROP
	$SUDO ${iptables_bin} -t mangle -P FORWARD DROP
	$SUDO ${iptables_bin} -t mangle -P POSTROUTING DROP
}


###############################################################################
# Log all the dropped incoming packets to the syslogd for debugging
##
log_all_dropped_incoming() {
	log "\t {LOG}   INCOMING: \t\t all dropped"

	iface=$1
	iptables_bin=$2

	# filter table
	${SUDO} ${iptables_bin} -t filter -A INPUT -i ${iface} -m limit --limit 2/min -j LOG --log-prefix "{INPUT-filter-Dropped} " --log-level 7

	# mangle table
	${SUDO} ${iptables_bin} -t mangle -A INPUT -i ${iface} -m limit --limit 2/min -j LOG --log-prefix "{INPUT-mangle-Dropped} " --log-level 7
}


###############################################################################
# Log all the dropped outgoing packets to the syslogd for debugging
##
log_all_dropped_outgoing() {
	log "\t {LOG}   OUTGOING: \t\t all dropped"

	iface=$1
	iptables_bin=$2

	# filter table
	${SUDO} ${iptables_bin} -t filter -A OUTPUT -o ${iface} -m limit --limit 2/min -j LOG --log-prefix "{OUTPUT-filter-Dropped} " --log-level 7

	# mangle table
	${SUDO} ${iptables_bin} -t mangle -A OUTPUT -o ${iface} -m limit --limit 2/min -j LOG --log-prefix "{OUTPUT-mangle-Dropped} " --log-level 7
}


###############################################################################
# Allow any RELATED or ESTABLISHED connections
##
allow_related_established() {
	log "{ALLOW} INCOMING & OUTGOING: \t related & established packets" 

	iptables_bin=$1

	# filter table
	$SUDO ${iptables_bin} -t filter -I INPUT 1 -m state --state RELATED,ESTABLISHED -j ACCEPT
	$SUDO ${iptables_bin} -t filter -I OUTPUT 1 -m state --state RELATED,ESTABLISHED -j ACCEPT

	# mangle table
	$SUDO ${iptables_bin} -t mangle -I PREROUTING 1 -m state --state RELATED,ESTABLISHED -j ACCEPT
	$SUDO ${iptables_bin} -t mangle -I INPUT 1 -m state --state RELATED,ESTABLISHED -j ACCEPT
	$SUDO ${iptables_bin} -t mangle -I OUTPUT 1 -m state --state RELATED,ESTABLISHED -j ACCEPT
	$SUDO ${iptables_bin} -t mangle -I POSTROUTING 1 -m state --state RELATED,ESTABLISHED -j ACCEPT
}


###############################################################################
# Allow all traffic from loopback interface
##
allow_loopback() {
	log "{ALLOW} INCOMING & OUTGOING: \t loopback interface"

	iptables_bin=$1

	# filter table
	$SUDO ${iptables_bin} -t filter -A INPUT -i lo -j ACCEPT
	$SUDO ${iptables_bin} -t filter -A OUTPUT -o lo -j ACCEPT

	# mangle table
	$SUDO ${iptables_bin} -t mangle -A PREROUTING -i lo -j ACCEPT
	$SUDO ${iptables_bin} -t mangle -A INPUT -i lo -j ACCEPT
	$SUDO ${iptables_bin} -t mangle -A OUTPUT -o lo -j ACCEPT
	$SUDO ${iptables_bin} -t mangle -A POSTROUTING -o lo -j ACCEPT
}


###############################################################################
# Allow outbound DHCP packets 
##
allow_DHCP_out() {
	log "\t {ALLOW} OUTGOING: \t\t DHCP"

	iface=$1
	iptables_bin=$2

	$SUDO ${iptables_bin} -t filter -A OUTPUT -o ${iface} -p udp --dport 67:68 --sport 67:68 -j ACCEPT
}


###############################################################################
# Allow inbound SSH packets 
##
allow_SSH_in() {
	log "\t {ALLOW} INCOMING: \t\t SSH"

	iface=$1
	iptables_bin=$2

	# filter table
	$SUDO ${iptables_bin} -t filter -A INPUT -i ${iface} -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT

	# mangle table
	$SUDO ${iptables_bin} -t mangle -A INPUT -o ${iface} -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
	$SUDO ${iptables_bin} -t mangle -A PREROUTING -o ${iface} -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
}


###############################################################################
# Allow outbound SSH packets 
##
allow_SSH_out() {
	log "\t {ALLOW} OUTGOING: \t\t SSH"

	iface=$1
	iptables_bin=$2

	# filter table
	$SUDO ${iptables_bin} -t filter -A OUTPUT -o ${iface} -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT

	# mangle table
	$SUDO ${iptables_bin} -t mangle -A OUTPUT -o ${iface} -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
	$SUDO ${iptables_bin} -t mangle -A POSTROUTING -o ${iface} -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
}


###############################################################################
# Allow outbound WHOIS packets 
##
allow_WHOIS_out() {
	log "\t {ALLOW} OUTGOING: \t\t WHOIS"

	iface=$1
	iptables_bin=$2

	# filter table
	$SUDO ${iptables_bin} -t filter -A OUTPUT -o ${iface} -p tcp -m tcp --dport 43 -m state --state NEW -j ACCEPT

	# mangle table
	$SUDO ${iptables_bin} -t mangle -A OUTPUT -o ${iface} -p tcp -m tcp --dport 43 -m state --state NEW -j ACCEPT
	$SUDO ${iptables_bin} -t mangle -A POSTROUTING -o ${iface} -p tcp -m tcp --dport 43 -m state --state NEW -j ACCEPT
}


###############################################################################
# Allow outbound SMTP packets 
##
allow_SMTP_out() {
	log "\t {ALLOW} OUTGOING: \t\t SMTP"

	iface=$1
	iptables_bin=$2

	$SUDO ${iptables_bin} -t filter -A OUTPUT -o ${iface} -p tcp -m tcp --dport 25 -m state --state NEW -j ACCEPT
}


###############################################################################
# Allow outbound DNS packets 
##
allow_DNS_out() {
	log "\t {ALLOW} OUTGOING: \t\t DNS"

	iface=$1
	iptables_bin=$2

	# filter table
	$SUDO ${iptables_bin} -t filter -A OUTPUT -o ${iface} -p udp -m udp --dport 53 -j ACCEPT

	# mangle table
	$SUDO ${iptables_bin} -t mangle -A OUTPUT -o ${iface} -p udp -m udp --dport 53 -j ACCEPT
	$SUDO ${iptables_bin} -t mangle -A POSTROUTING -o ${iface} -p udp -m udp --dport 53 -j ACCEPT
}


###############################################################################
# Allow inbound ping(ICMP) packets 
##
allow_ping_in() {
	log "{ALLOW} INCOMING: \t\t ping"

	iface=$1
	iptables_bin=$2

	# filter table
	$SUDO ${iptables_bin} -t filter -A INPUT -i ${iface} -p icmp --icmp-type echo-reply -j ACCEPT

	# mangle table
	$SUDO ${iptables_bin} -t mangle -A PREROUTING -i ${iface} -p icmp --icmp-type echo-reply -j ACCEPT
	$SUDO ${iptables_bin} -t mangle -A INPUT -i ${iface} -p icmp --icmp-type echo-reply -j ACCEPT
}


###############################################################################
# Allow outbound ping(ICMP) packets
##
allow_ping_out() {
	log "\t {ALLOW} OUTGOING: \t\t ping"

	iface=$1
	iptables_bin=$2

	# filter table
	$SUDO ${iptables_bin} -t filter -A OUTPUT -o ${iface} -p icmp --icmp-type echo-request -j ACCEPT

	# mangle table
	$SUDO ${iptables_bin} -t mangle -A OUTPUT -o ${iface} -p icmp --icmp-type echo-request -j ACCEPT
	$SUDO ${iptables_bin} -t mangle -A POSTROUTING -o ${iface} -p icmp --icmp-type echo-request -j ACCEPT
}


###############################################################################
# Allow outbound NTP packets 
##
allow_NTP_out() {
	log "\t {ALLOW} OUTGOING: \t\t NTP"

	iface=$1
	iptables_bin=$2

	$SUDO ${iptables_bin} -t filter -A OUTPUT -o ${iface} -p udp --dport 123 --sport 123 -j ACCEPT
}


###############################################################################
# Allow outbound HTTP & HTTPS packets 
##
allow_HTTP_out() {
	log "\t {ALLOW} OUTGOING: \t\t HTTP"

	iface=$1
	iptables_bin=$2

	# filter table
	$SUDO ${iptables_bin} -t filter -A OUTPUT -o ${iface} -p tcp --dport 80 -m state --state NEW -j ACCEPT
	$SUDO ${iptables_bin} -t filter -A OUTPUT -o ${iface} -p tcp --dport 443 -m state --state NEW -j ACCEPT

	# mangle table
	$SUDO ${iptables_bin} -t mangle -A OUTPUT -o ${iface} -p tcp --dport 80 -m state --state NEW -j ACCEPT
	$SUDO ${iptables_bin} -t mangle -A OUTPUT -o ${iface} -p tcp --dport 443 -m state --state NEW -j ACCEPT
	$SUDO ${iptables_bin} -t mangle -A POSTROUTING -o ${iface} -p tcp --dport 80 -m state --state NEW -j ACCEPT
	$SUDO ${iptables_bin} -t mangle -A POSTROUTING -o ${iface} -p tcp --dport 443 -m state --state NEW -j ACCEPT
}


###############################################################################
# Allow inbound skype packets 
##
allow_skype_in() {
	log "\t {ALLOW} INCOMING: \t\t skype"

	iface=$1
	iptables_bin=$2

	$SUDO ${iptables_bin} -t filter -A INPUT -i ${iface} -p udp --dport 16514 -j ACCEPT
	$SUDO ${iptables_bin} -t filter -A INPUT -i ${iface} -p tcp --dport 16514 -j ACCEPT
}


###############################################################################
# Apply the firewall rules to all the interfaces that are up
##
firewall_all_ifaces() {
	iptables_bin=$1

	INET_FACES=`$IFCONFIG -s | $GREP -vi 'kernel' | $GREP -vi 'iface' | $GREP -v 'lo' | $AWK '{print $1}'`
	for iface in $INET_FACES
	do
		log "============== ${iface} =============="

		# allow incoming requests
		#allow_SSH_in ${iface}
		#allow_ping_in ${iface}
		allow_skype_in ${iface} ${iptables_bin}

		# allow outcoming requests
		allow_DHCP_out ${iface} ${iptables_bin}
		allow_DNS_out ${iface} ${iptables_bin}
		allow_HTTP_out ${iface} ${iptables_bin}
		allow_NTP_out ${iface} ${iptables_bin}
		allow_ping_out ${iface} ${iptables_bin}
		allow_SMTP_out ${iface} ${iptables_bin}
		allow_SSH_out ${iface} ${iptables_bin}
		allow_WHOIS_out ${iface} ${iptables_bin}

		# has to be the last rules to catch only the dropped packets
		log_all_dropped_incoming ${iface} ${iptables_bin}
		log_all_dropped_outgoing ${iface} ${iptables_bin}
	done
}


###############################################################################
# Is Root
##
is_root() {
	$LS $ROOT_DIR >/dev/null 2>/dev/null
	return $?
}


###############################################################################
# Main function
##
main() {
	if [ "x$(is_root)" != "x0" ]; then
		log "Not a root!"
	fi

	log
	log "-------------- KERNEL FEATURES ---------------"
	disable_enable_kernel_features

	# Handle IPv4 based firewall
	if [ ! -z $IPv4TABLES ]; then
		log
		log "-------------- IPv4 ---------------"
		clear_all_rules $IPv4TABLES
		default_drop_all $IPv4TABLES
		allow_related_established $IPv4TABLES
		allow_loopback $IPv4TABLES
		drop_IANA_reserved_ips $IPv4TABLES
		firewall_all_ifaces $IPv4TABLES
	fi

	# Handle IPv6 based firewall
	if [ ! -z $IPv6TABLES ]; then
		log
		log "-------------- IPv6 ---------------"
		clear_all_rules $IPv6TABLES
		default_drop_all $IPv6TABLES
	fi
}

#set -x
main
