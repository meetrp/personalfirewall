#!/bin/bash

###############################################################################
# Find the CIDR address range for a given URL(s)
#
# This is especially useful while trying to blacklist or whitelist a certain
# domain in your IPTables.
#
# Note: Used a ip-range to CIDR perl script written by Krishchan Jodies.
# My special thanks to Krishchan for helping me to overcome my temporary
# limitation of doing the conversion in 'bash'
#
# Reference:
#	* IP Calculator: http://jodies.de/ipcalc
#
###############################################################################


# Absolute paths for helper scripts/commands
AWK=`which awk`
GREP=`which grep`
HOST=`which host`
SUDO=`which sudo`
WHOIS=`which whois`
PERL=`which perl`
IPCALC="./ipcalc -r"


###############################################################################
# CIDR function
##
CIDR() {
	url="$1"

	#cidr_array=
	ips=$( ${SUDO} ${HOST} ${url} | ${GREP} "has address" | ${AWK} '{print $4}' )
	if [ ! -z ${#ips} ]; then
		count=1
		for ip in $ips
		do
			# sometimes the CIDR is directly available in the 'whois' response
			cidr=$( ${SUDO} ${WHOIS} ${ip} | ${GREP} "CIDR" | ${AWK} '{print $2}' )
			if [ -z ${cidr} ]; then
				# if the CIDR is not available then the IP-range is available, which
				# need to be converted into the CIDR
				iprange=$( ${SUDO} ${WHOIS} ${ip} | ${GREP} "inetnum" )
				begin=$( echo $iprange | ${AWK} '{print $2}' )
				end=$( echo $iprange | ${AWK} '{print $4}' )

				cidr=$( ${SUDO} ${PERL} ${IPCALC} ${begin} ${end} | ${GREP} -v "deaggregate" )
			fi

			cidr_array[$count]="${cidr}"
			count=`expr $count \+ 1`
		done
	fi

	echo "${cidr_array[*]}"
}


###############################################################################
# Main
##
#set -x
if [ $# -lt 1 ]; then
	return 1
fi

while [ $# -ge 1 ]; do
	url="$1"
	shift

	cidr=$( CIDR "${url}" )
	echo "${url} : ${cidr}"

done
