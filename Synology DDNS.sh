# Cloudflare DDNS script for Synology NAS.
# DDNS setting in Synology:
# Server Name: Domain
# Username/Email: CF Region ID
# Password: API token with DNS writing permission

wget https://raw.githubusercontent.com/joshuaavalon/SynologyCloudflareDDNS/master/cloudflareddns.sh -O /sbin/cloudflareddns.sh
chmod +x /sbin/cloudflareddns.sh
cat >> /etc.defaults/ddns_provider.conf << EOF
[Cloudflare]
        modulepath=/sbin/cloudflareddns.sh
        queryurl=https://www.cloudflare.com
        website=https://www.cloudflare.com
EOF
vi /sbin/cloudflareddns.sh
