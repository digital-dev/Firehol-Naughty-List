# Firehol Naughty List.

## Description

A simple bash script utilizing ipset and iptables to dynamically block large sets of IP addresses.
It blocks IP addresses belonging to the following blacklists, updated daily.

- AlienVault.com IP reputation database
- pfBlockerNG Malicious Threats
- BadIPS.com in category any with score above 2 
- Blocklist.de IPs that have been detected by fail2ban in the last 48 hours
- Botscout 30d
- Bogon Networks - Unallocated (Free) Address Space
- CleanTalk Recurring HTTP Spammers
- CruzIt.com IPs of compromised machines scanning for vulnerabilities and DDOS attacks
- Darklist fail2ban reporting
- Address that correspond to datacenters, co-location centers, shared and virtual webhosting providers. 
- Dshield 30d top 20 attacking class C (/24) subnets over the last 30 days
- Malicious Botnets Serving Various Malware Families

On average, this comes out to be around 700,000 IP addresses and 5,900 Subnets, totaling approximately 2.2 million unique IP addresses.
This script features very fast execution time compared to similar scripts, creating importable ipsets and reducing IO operations to optimize running on single board computers.
Tested with Odroid Xu4, Raspi 3, Raspi 4, Raspi 0.

## How to use

Download or clone the repository:
git clone https://github.com/digital-dev/Firehol-Naughty-List.git

Edit the script to whitelist your local network. (Defaults to 192.168.1.0 - 192.168.1.255)

_network="192.168.1.0/24

Make the script executable.
chmod +x blacklist.sh

Finally, run the script to test or create your blacklists.
./blacklist.sh

If successful, you should be prompted to confirm your changes to iptables.
After 20 seconds, if no confirmation is given, the script will restore iptables to its former state.

If needed, you can modify the badips-cron version of the script with all your necessary changes to automate updates to the blacklists.
cp badips-cron.sh /etc/cron/daily/bad-ips && chmod +x /etc/cron/daily/bad-ips