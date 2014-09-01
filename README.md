Personal Firewall
=================

Personal firewall for my laptop using iptables &amp; ipv6tables. The idea is to protect my laptop while on open network. The idea behind my firewall & details of each step has been detailed in my blog: http://tech.meetrp.com/blog/iptables-personal-firewall-to-protect-my-laptop

myfirewall.sh
=============
Execute this shell script to set the firewall temporarily for this login session. <b>Don't forget to run as sudo</b> Also this script has been written to apply the same rules on all the available 'active' network interfaces. As you can see below, these set of rules have been applied on both 'eth0' as well as 'wlan0'. Also this scripts enables or disables a few kernel features through the '/proc' interface.

```
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


