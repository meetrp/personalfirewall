Personal Firewall
=================

Personal firewall for my laptop using iptables &amp; ipv6tables. The idea is to protect my laptop while on open network. The idea behind my firewall & details of each step has been detailed in my blog: http://tech.meetrp.com/blog/iptables-personal-firewall-to-protect-my-laptop

myfirewall.sh
=============
Execute this shell script to set the firewall temporarily for this login session. <b>Don't forget to run as sudo</b> Also this script has been written to apply the same rules on all the available 'active' network interfaces. As you can see below, these set of rules have been applied on both 'eth0' as well as 'wlan0'. Also this scripts enables or disables a few kernel features through the '/proc' interface.

```bash
$> sudo ./myfirewall.sh
[Monday 01 September 2014 21:38:06] Not a root!

[Monday 01 September 2014 21:38:06] -------------- KERNEL FEATURES ---------------
[Monday 01 September 2014 21:38:06] {IGNORE} 		 ICMP echo broadcasts
[Monday 01 September 2014 21:38:06] {ENABLE} 		 log for all unroutable packets
[Monday 01 September 2014 21:38:06] {ENABLE} 		 reverse path filtering
[Monday 01 September 2014 21:38:06] {ENABLE} 		 SYN cookies protetion
[Monday 01 September 2014 21:38:06] {DISABLE} 		 ICMP redirects
[Monday 01 September 2014 21:38:06] {DISABLE} 		 IP forwarding
[Monday 01 September 2014 21:38:06] {DISABLE} 		 source route

[Monday 01 September 2014 21:38:06] -------------- IPv4 ---------------
[Monday 01 September 2014 21:38:06] clear all rules
[Monday 01 September 2014 21:38:06] default drop
[Monday 01 September 2014 21:38:07] {ALLOW} INCOMING & OUTGOING: 	 related & established packets
[Monday 01 September 2014 21:38:07] {ALLOW} INCOMING & OUTGOING: 	 loopback interface
[Monday 01 September 2014 21:38:07] {DROP} INCOMING: 			 all IANA reserved IPs
[Monday 01 September 2014 21:38:07] ============== eth0 ==============
[Monday 01 September 2014 21:38:07] 	 {ALLOW} INCOMING: 		 skype
[Monday 01 September 2014 21:38:07] 	 {ALLOW} OUTGOING: 		 DHCP
[Monday 01 September 2014 21:38:07] 	 {ALLOW} OUTGOING: 		 DNS
[Monday 01 September 2014 21:38:07] 	 {ALLOW} OUTGOING: 		 HTTP
[Monday 01 September 2014 21:38:07] 	 {ALLOW} OUTGOING: 		 NTP
[Monday 01 September 2014 21:38:07] 	 {ALLOW} OUTGOING: 		 ping
[Monday 01 September 2014 21:38:07] 	 {ALLOW} OUTGOING: 		 SMTP
[Monday 01 September 2014 21:38:07] 	 {ALLOW} OUTGOING: 		 SSH
[Monday 01 September 2014 21:38:07] 	 {ALLOW} OUTGOING: 		 WHOIS
[Monday 01 September 2014 21:38:07] 	 {LOG}   INCOMING: 		 all dropped
[Monday 01 September 2014 21:38:07] 	 {LOG}   OUTGOING: 		 all dropped
[Monday 01 September 2014 21:38:07] ============== wlan0 ==============
[Monday 01 September 2014 21:38:07] 	 {ALLOW} INCOMING: 		 skype
[Monday 01 September 2014 21:38:07] 	 {ALLOW} OUTGOING: 		 DHCP
[Monday 01 September 2014 21:38:07] 	 {ALLOW} OUTGOING: 		 DNS
[Monday 01 September 2014 21:38:07] 	 {ALLOW} OUTGOING: 		 HTTP
[Monday 01 September 2014 21:38:07] 	 {ALLOW} OUTGOING: 		 NTP
[Monday 01 September 2014 21:38:07] 	 {ALLOW} OUTGOING: 		 ping
[Monday 01 September 2014 21:38:07] 	 {ALLOW} OUTGOING: 		 SMTP
[Monday 01 September 2014 21:38:07] 	 {ALLOW} OUTGOING: 		 SSH
[Monday 01 September 2014 21:38:07] 	 {ALLOW} OUTGOING: 		 WHOIS
[Monday 01 September 2014 21:38:07] 	 {LOG}   INCOMING: 		 all dropped
[Monday 01 September 2014 21:38:07] 	 {LOG}   OUTGOING: 		 all dropped

[Monday 01 September 2014 21:38:07] -------------- IPv6 ---------------
[Monday 01 September 2014 21:38:07] clear all rules
[Monday 01 September 2014 21:38:07] default drop
```

loadiptables & saveiptables
===========================
These are required if you want to persist the IPTables rules. The saving & restoring happens during network-down & network-up, respectively. To do so:

```bash
$> sudo cp loadiptables /etc/network/if-up.d/

$> sudo cp saveiptables /etc/network/if-down.d/
```

toCIDR.sh
=========
This script is used to convert given URL(s) to their CIDRs. For example:

```bash
$> toCIDR.sh www.facebook.com www.google.com
www.facebook.com : 31.13.91.0/24
www.google.com : 74.125.0.0/16 74.125.0.0/16 74.125.0.0/16 74.125.0.0/16 74.125.0.0/16 74.125.0.0/16
```

In this example, these CIDRs can be used in the IPTables rules set to add specific rules to handle Facebook & Google traffic. Please run these at your server as these IPs are geo-specific, or so I think! ;)

ipcalc
======
This 'perl' script is required by toCIDR.sh script to convert IP ranges to CIDR notation. This script has been borrowed from http://jodies.de/ipcalc. I thank Krischan Jodies<ipcalc-200808@jodies.de> for scripting such a beautiful masterpiece that works brilliantly. There are various usages to this but what I use is:

```bash
$> perl ipcalc -r 192.168.1.0 192.168.1.250
deaggregate 192.168.1.0 - 192.168.1.250
192.168.1.0/25
192.168.1.128/26
192.168.1.192/27
192.168.1.224/28
192.168.1.240/29
192.168.1.248/31
```

These the CIDRs that is printed out by toCIDR.sh script.
