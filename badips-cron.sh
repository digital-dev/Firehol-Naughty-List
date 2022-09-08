#!/bin/bash
# Firehol Secure IPSET Blacklist
# Name of database (will be downloaded with this name)
_input=badips.db
# Whitelist CIDR Mask.
_network="192.168.2.0/28"

## Get bad IP data using https://github.com/firehol/blocklist-ipsets
# AlienVault.com IP reputation database
{
wget -qO- https://reputation.alienvault.com/reputation.generic
# pfBlockerNG Malicious Threats
wget -qO- https://gist.githubusercontent.com/BBcan177/bf29d47ea04391cb3eb0/raw
wget -qO- https://gist.githubusercontent.com/BBcan177/d7105c242f17f4498f81/raw
# BadIPS.com in category any with score above 2 
wget -qO- https://www.badips.com/get/list/any/2
# Blocklist.de IPs that have been detected by fail2ban in the last 48 hours
wget -qO- http://lists.blocklist.de/lists/all.txt
# Botscout 30d
wget -qO- http://botscout.com/last_caught_cache.htm
# Bogon Networks - Unallocated (Free) Address Space
wget -qO- http://www.cidr-report.org/bogons/freespace-prefix.txt
# CleanTalk Recurring HTTP Spammers
wget -qO- https://cleantalk.org/blacklists/updated_today
# CruzIt.com IPs of compromised machines scanning for vulnerabilities and DDOS attacks
wget -qO- http://www.cruzit.com/xwbl2txt.php
# Darklist fail2ban reporting
wget -qO- http://www.darklist.de/raw.php
# Address that correspond to datacenters, co-location centers, shared and virtual webhosting providers. 
wget -qO- https://raw.githubusercontent.com/client9/ipcat/master/datacenters.csv
# Dshield 30d top 20 attacking class C (/24) subnets over the last 30 days
wget -qO- http://feeds.dshield.org/block.txt
# Malicious Botnet Serving Various Malware Families
wget -qO- https://raw.githubusercontent.com/eSentire/malfeed/master/crazyerror.su_watch_ip.lst
} >> $_input

# Verify or create our IP sets.
if ipset -L hash_ip | grep -q 'hash_ip'; then true;else ipset create hash_ip hash:ip maxelem 5000000; fi
if ipset -L hash_net | grep -q 'hash_net'; then true;else ipset create hash_net hash:net maxelem 5000000; fi

# Flush the IP Sets.
ipset flush hash_ip
ipset flush hash_net

# Filter and create our datasets
grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" $_input | sort -n > hash_ip
grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}/[0-9]{1,2}" $_input | sort -n > hash_net
sed -i -e 's/0.0.0.0//g' hash_ip
sed -i '/^$/d' hash_ip

# Create our ipset lists
echo "create hash_ip hash:ip family inet hashsize 1024 maxelem 5000000" > hash_ip.ipset
echo "create hash_net hash:net family inet hashsize 1024 maxelem 5000000" > hash_net.ipset
sed -e 's/^/add hash_ip /' hash_ip >> hash_ip.ipset
sed -e 's/^/add hash_net /' hash_net >> hash_net.ipset

# Import blacklist to IPSET
ipset restore -! < hash_ip.ipset
ipset restore -! < hash_net.ipset

# Whitelist our local network
iptables -C INPUT -s 127.0.0.1 -j ACCEPT || iptables -A INPUT -s 127.0.0.1 -j ACCEPT
iptables -C INPUT -s $_network -j ACCEPT || iptables -A INPUT -s $_network -j ACCEPT
# Insert or append to iptables
iptables -C INPUT -m set --match-set hash_ip src -j LOG --log-prefix "Drop Bad IP List " || iptables -A INPUT -m set --match-set hash_ip src -j LOG --log-prefix "Drop Bad IP List "
iptables -C INPUT -m set --match-set hash_ip src -j DROP || iptables -A INPUT -m set --match-set hash_ip src -j DROP
iptables -C INPUT -m set --match-set hash_net src -j LOG --log-prefix "Drop Bad IP List " || iptables -A INPUT -m set --match-set hash_net src -j LOG --log-prefix "Drop Bad IP List "
iptables -C INPUT -m set --match-set hash_net src -j DROP || iptables -A INPUT -m set --match-set hash_net src -j DROP

# Remove temporary files
rm $_input
rm hash_ip
rm hash_net
rm hash_ip.ipset
rm hash_net.ipset

exit 0