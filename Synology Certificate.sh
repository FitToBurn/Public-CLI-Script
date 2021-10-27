# Certificate installation script for Synology NAS.
# Please disable http2 in Synology settings.
# Command for auto renew task/generate renew logs:
# sh /path/to/script.sh >> /path/to/renewlog.txt 2>&1
cd ~
wget https://github.com/acmesh-official/acme.sh/archive/master.tar.gz
tar xvf master.tar.gz
cd acme.sh-master/
./acme.sh --install --nocron --home /usr/local/share/acme.sh --accountemail "[Cloudflare Email]"
source ~/.profile
export CF_Email="[Cloudflare Email]"
export CF_Key="[CF Global API Key]"
cd /usr/local/share/acme.sh
export CERT_DOMAIN="*.example.com"
export CERT_DNS="dns_cf"
./acme.sh --issue --home . -d "$CERT_DOMAIN" --dns "$CERT_DNS" --force
cd /usr/local/share/acme.sh
export SYNO_Username='[Synology Username]'
export SYNO_Password='[Password]'
export SYNO_Scheme="https"
export SYNO_Port="[https port]"
export SYNO_DID=[2-factor auth cookie]
export SYNO_Certificate="[Certificate Description]"
./acme.sh --insecure --deploy --home . -d "$CERT_DOMAIN" --deploy-hook synology_dsm
cp -f /usr/local/share/acme.sh//"*.example.com"/"fullchain.cer" /path/to/savefolder/
cp -f /usr/local/share/acme.sh//"*.example.com"/"*.example.com.key" /path/to/savefolder/
cd /path/to/savefolder/
mv "*.example.com.key" privkey.key
synoservice -restart pkgctl-Docker

# auto renew
# sh /path/to/script.sh >> /path/to/log.txt 2>&1