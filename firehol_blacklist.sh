#!/bin/bash
##############################################################################################################################
# ███████╗██╗██████╗ ███████╗██╗  ██╗ ██████╗ ██╗         ██████╗ ██╗      █████╗  ██████╗██╗  ██╗██╗     ██╗███████╗████████╗
# ██╔════╝██║██╔══██╗██╔════╝██║  ██║██╔═══██╗██║         ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██║     ██║██╔════╝╚══██╔══╝
# █████╗  ██║██████╔╝█████╗  ███████║██║   ██║██║         ██████╔╝██║     ███████║██║     █████╔╝ ██║     ██║███████╗   ██║   
# ██╔══╝  ██║██╔══██╗██╔══╝  ██╔══██║██║   ██║██║         ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║     ██║╚════██║   ██║   
# ██║     ██║██║  ██║███████╗██║  ██║╚██████╔╝███████╗    ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗███████╗██║███████║   ██║   
# ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝╚══════╝   ╚═╝   
# Firehol Secure IPSET Blacklist
# Name of database (will be downloaded with this name)
_input=badips.db
# Whitelist CIDR Mask.
_network="192.168.1.0/24"

## Get bad IP data using https://github.com/firehol/blocklist-ipsets
if [ ! -d blocklist-ipsets ]; then
	git clone https://github.com/firehol/blocklist-ipsets
	cd blocklist-ipsets || exit
	# Primary Lists (Does not include ISP's)
	find . -maxdepth 1 -name 'feodo*.*set' -o \
	-name '*palevo.*set' -o \
	-name 'sslbl*.*set' -o \
	-name '*zeus.*set' -o \
	-name '*dshield*.*set' -o \
	-name '*spamhaus*.*set' -o \
	-name '*bogons*.*set'-o \
	-name '*open*.*set' -o \
	-name 'blocklist_de*.*set' -o \
	-name '*alien*.*set' -o \
	-name 'bi*.*set' -o \
	-name 'coinbl*.*set' -o \
	-name 'datacenters.*set' -o \
	-name '*ponmocup*.*set' -o \
	-name '*esentire*.*set' -o \
	-name 'botscout*.*set' -o \
	-name '*webexploit*.*set' -o \
	-name '*php*.*set' -o \
	# The entry below (*rox*.*set) will block many proxies and anonimizers. To disable this, comment the below line out with #
	-name '*rox*.*set' -o \
	-name 'bbca*.*set' | 
	sort | xargs cat >> ../$_input
	# Country Blacklisting (Default whitelist US, GB, AU, CA, NZ)
	find ./geolite2_country/ -iname "country_*.*set" ! -name "*_us*.*set" ! -name "*_gb*.*set" ! -name "*_au*.*set" ! -name "*_ca*.*set" ! -name "*_nz*.*set" | sort | xargs cat >> ../$_input
	cd .. || exit
else
	cd blocklist-ipsets || exit
	git pull
	# Primary Lists (Does not include ISP's)
	find . -maxdepth 1 -iname '*.*set' -not -name '*isp*.*set' | sort | xargs cat >> ../$_input
	# Country Blacklisting (Default whitelist US, GB, AU, CA, NZ)
	find ./geolite2_country/ -iname "country_*.*set" ! -name "*_us*.*set" ! -name "*_gb*.*set" ! -name "*_au*.*set" ! -name "*_ca*.*set" ! -name "*_nz*.*set" | sort | xargs cat >> ../$_input
	cd .. || exit
fi

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
rm hash_ip
rm hash_net
# Import blacklist to IPSET
ipset restore -! < hash_ip.ipset
ipset restore -! < hash_net.ipset

# Create a backup of our IPTables Firewall Prior to Editing.
iptables-save > iptables.bak

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
rm ./*.ipset
exit 0
