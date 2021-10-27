#!/bin/bash
green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}
red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}
yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}
yteal(){
    echo -ne "\033[34m\033[01m$1\033[0m"
    echo -e "\033[36m\033[01m$2\033[0m"
}
enter_promote(){
    echo -ne "\033[34m\033[01m$1\033[0m"
}

# Todo
# 1.优化防火墙 仅block http口
# 2.acme.sh 使用Zerossl优化
# 3.Cert 结束后 先检测是否有docker.service再决定要不要restart

initialize(){
    
    #开启BBR加速
    BBRCHECK=$(sysctl -n net.ipv4.tcp_congestion_control)
    if [ "$BBRCHECK" != "bbr" ]; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        sysctl -n net.ipv4.tcp_congestion_control
        lsmod | grep bbr
        green "BBR enabled."
    else
        yellow "BBR is already enabled."
    fi

    #关闭防火墙和SELINUX
    systemctl stop firewalld
    systemctl disable firewalld
    CHECK=$(grep SELINUX= /etc/selinux/config | grep -v "#")
    if [ "$CHECK" == "SELINUX=enforcing" ]; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
    if [ "$CHECK" == "SELINUX=permissive" ]; then
        sed -i 's/SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
    yum -y install bind-utils wget unzip zip curl tar
    yum -y install libseccomp-devel

}

cert(){
    green "====================================="
    echo
    yteal "" " Enter the domain name of your VPS:"
    enter_promote " Domain:"
    read your_domain
    echo
    green "====================================="
    real_addr=`ping ${your_domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
    local_addr=`curl ipv4.icanhazip.com`
    if [ $real_addr == $local_addr ] ; then
        green "==============================="
        green "Domain name resolves correctly."
        green "==============================="
        rpm -Uvh http://nginx.org/packages/centos/7/noarch/RPMS/nginx-release-centos-7-0.el7.ngx.noarch.rpm
            yum install -y nginx
        systemctl enable nginx.service
        #设置伪装站
        rm -rf /usr/share/nginx/html/*
        cd /usr/share/nginx/html/
        wget https://github.com/atrandys/v2ray-ws-tls/raw/master/web.zip
            unzip web.zip
        systemctl restart nginx.service
        #申请https证书 acme.sh default由Let's Encrypt 改为 Zerossl
        mkdir /usr/src/cert
        curl https://get.acme.sh | sh
        ~/.acme.sh/acme.sh  --set-default-ca --server letsencrypt
        ~/.acme.sh/acme.sh  --issue  -d $your_domain  --webroot /usr/share/nginx/html/
        ~/.acme.sh/acme.sh  --installcert  -d  $your_domain   \
            --key-file   /usr/src/cert/private.key \
            --fullchain-file /usr/src/cert/fullchain.cer \
            --reloadcmd  "systemctl force-reload  nginx.service"
        if test -s /usr/src/cert/fullchain.cer; then
            #Restart docker
            systemctl restart docker
            if [ "$mode" == "0" ];then
                start_menu 1
            fi
            return 0
        else
            red "=================================="
            red "Failed to install SSL Certificate."
            red "=================================="
            return 1
        fi
	
    else
        red "======================="
        red "Domain resolving error."
        red "======================="
        return 1
    fi
}

protocol_config(){
    randompasswd=$(cat /dev/urandom | head -1 | md5sum | head -c 12)
    randomssport=$(shuf -i 10000-14999 -n 1)
    # randomsnellport=$(shuf -i 15000-19999 -n 1)

    green "========================================================"
    echo
    yellow " Enter the PASSWORD for Trojan, Shadowsocks:"
    yteal " ==Default==:" "${randompasswd}"
    enter_promote " Your choice:"
    read mainpasswd
    [ -z "${mainpasswd}" ] && mainpasswd=${randompasswd}
    echo

    yellow " Enter the fallback port for Trojan [1-65535]:"
    yteal " ==Default==:" "80"
    enter_promote " Your choice:"
    read fallbackport
    [ -z "${fallbackport}" ] && fallbackport="80"
    echo

    yellow " Enter the port for Shadowsocks [1-65535]:"
    yteal " ==Default==:" "${randomssport}"
    enter_promote " Your choice:"
    read ssport
    [ -z "${ssport}" ] && ssport=${randomssport}
    echo

    green "========================================================"
    echo

}

install_docker(){
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    systemctl start docker
    systemctl enable docker
    systemctl enable containerd

    ###===Current List===###
    #- Xray
    #~ Portainer
    #~ SubConverter
    #~ livemonitor
    #~ downloader
    #+ V2Ray

    if [ "$containeropt" == "M" ];then
        # Portainer
        docker pull portainer/portainer-ce:latest
        docker volume create portainer_data
        docker run -d -p 600:9443 -p 8000:8000 --name=portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker/volumes/portainer_data/:/data/ -v /usr/src/cert:/cert portainer/portainer-ce --sslcert /cert/fullchain.cer --sslkey /cert/private.key

        # SubConverter
        docker pull tindy2013/subconverter:latest
        docker run -d --name=subconverter --restart=always -p 25500:25500 tindy2013/subconverter
        cat > /etc/nginx/nginx.conf <<-EOF
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;
include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;
    include /etc/nginx/conf.d/*.conf;

    server {
        listen       80 default_server;
        listen       [::]:80 default_server;
        server_name  _;
        root         /usr/share/nginx/html;

        include /etc/nginx/default.d/*.conf;

        location / {
        }

        error_page 404 /404.html;
            location = /40x.html {
        }

        error_page 500 502 503 504 /50x.html;
            location = /50x.html {
        }
    }

    server {
        listen 500 ssl http2;
        server_name  _;
        gzip on;
        ssl_certificate /usr/src/cert/fullchain.cer;
        ssl_certificate_key /usr/src/cert/private.key;

        location / {
            proxy_pass http://127.0.0.1:25500/;
            proxy_set_header  Host                \$http_host;
            proxy_set_header  X-Real-IP           \$remote_addr;
        }
    }    

    server {
        listen 501 ssl http2;
        server_name  _;
        gzip on;
        ssl_certificate /usr/src/cert/fullchain.cer;
        ssl_certificate_key /usr/src/cert/private.key;

        location / {
            proxy_pass http://127.0.0.1:25501/;
            proxy_set_header  Host                \$http_host;
            proxy_set_header  X-Real-IP           \$remote_addr;
        }
    } 

}
EOF
        # livemonitor
        docker pull bigdaddywrangler/livemonitor
        docker volume create monitor
        cat > /var/lib/docker/volumes/monitor/config.json <<-EOF
{
	"submonitor_dic": {
        "1": {"class": "TwitterTweet", "target": "POTUS", "target_name": "Biden", "config_name": "twitter_config"}
    },
    "twitter_config": {
        "interval": 60,
        "timezone": 8,
        "vip_dic": {
            "POTUS": {"test": 1},
        },
        "word_dic": {
        },
        "cookies": {},
        "proxy": {},
        "push_list": [
            {"type": "discord", "id": "dc webhook", "color_dic": {"test": 1}}
        ]
    }
}
EOF
        docker run -d --network=host --name=livemonitor --restart=always -v /var/lib/docker/volumes/monitor/config.json:/usr/bin/config.json bigdaddywrangler/livemonitor:latest

        # downloader
        docker pull bigdaddywrangler/downloader
        docker run -d --name=vps-downloader --restart=always -p 25501:25501 bigdaddywrangler/downloader:latest
        
        nginx -s reload
    fi

    # Xray
#     docker pull teddysun/xray:latest
#     docker volume create xray_config
#     cat > /var/lib/docker/volumes/xray_config/config.json <<-EOF
# {
#   "log": {
#     "loglevel": "warning"
#   },
#   "inbounds": [
#     {
#       "port": 443, 
#       "protocol": "vless",
#       "settings": {
#         "clients":[{
#                     "id": "[UUID]",//SetUUID, better to generate one in the script
#                     "flow": "xtls-rprx-direct"
#                 }],
#         "decryption": "none",
#         "fallbacks": [{
#                     "dest": 444,
#                     "xver": 1
#                 }]
#       },
#       "streamSettings": {
#         "network": "tcp",
#         "security": "xtls",
#         "xtlsSettings": {
#           "alpn": ["http/1.1"],
#           "certificates": [{
#             "certificateFile": "/cert/fullchain.cer",
#             "keyFile": "/cert/private.key"
#           }]
#         }
#       }
#     },
#     {
#         "port": 444,
#         "listen": "127.0.0.1",
#         "protocol": "trojan",
#         "settings": {
#             "clients": [{"password": "$mainpasswd"}],
#             "fallbacks": [{"dest": $fallbackport}]
#         },
#         "streamSettings": {
#             "network": "tcp",
#             "security": "none",
#             "tcpSettings": {
#                 "acceptProxyProtocol": true
#             }
#         }
#     },
#     {
#       "port": $ssport, 
#       "protocol": "shadowsocks",
#       "settings":{
#           "method": "chacha20-ietf-poly1305",
#           "ota": false, 
#           "password": "$mainpasswd"
#       }
#     }
#   ],
#   "outbounds": [{ 
#     "protocol": "freedom"
#   }]
# }
# EOF
#     docker run -d --network=host --name xray --restart=always -v /var/lib/docker/volumes/xray_config/:/etc/xray/ -v /usr/src/cert:/cert teddysun/xray

    #V2fly
    docker pull v2fly/v2fly-core:latest
    docker volume create v2fly_config
	  cat > /var/lib/docker/volumes/v2fly_config/config.json <<-EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 443, 
      "protocol": "trojan",
      "settings": {
        "clients":[{"password": "$mainpasswd"}],
        "fallbacks": [{"dest": $fallbackport}]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["http/1.1"],
          "certificates": [{
            "certificateFile": "/cert/fullchain.cer",
            "keyFile": "/cert/private.key"
          }]
        }
      }
    },
    {
      "listen": "0.0.0.0",
      "port": $ssport, 
      "protocol": "shadowsocks",
      "settings":{
          "method": "chacha20-ietf-poly1305",
          "ota": false, 
          "password": "$mainpasswd"
      }
    }
  ],
  "outbounds": [{ 
    "protocol": "freedom"
  }]
}
EOF
    docker run -d --network=host --name=v2fly --restart=always -v /var/lib/docker/volumes/v2fly_config/config.json:/etc/v2ray/config.json -v /usr/src/cert:/cert v2fly/v2fly-core

    if [ "$mode" == "0" ];then
        start_menu 2        
    fi
    
}

ssh_update_config(){

    randomsshport=$(shuf -i 20000-29999 -n 1)
    randomadminpasswd=$(cat /dev/urandom | head -1 | md5sum | head -c 16)

    green "============================================="
    echo
    yellow " Enter a new SSH port [1-65535]:"
    yteal " ==Default==:" "${randomsshport}"
    enter_promote " Your choice:"
    read sshport
    [ -z "${sshport}" ] && sshport=${randomsshport}
    echo

    yellow " Enter a USERNAME for new admin account:"
    yteal " ==Default==:" "TempAdmin"
    enter_promote " Your choice:"
    read newusername
    [ -z "${newusername}" ] && newusername="TempAdmin"
    echo

    yellow " Enter a PASSWORD for ${newusername}:"
    yteal " ==Default==:" "${randomadminpasswd}"
    enter_promote " Your choice:"
    read adminpasswd
    [ -z "${adminpasswd}" ] && adminpasswd=${randomadminpasswd}
    echo
    green "============================================="
    echo

}

ssh_update(){
  adduser ${newusername}
  echo ${adminpasswd} | passwd ${newusername} --stdin
  chmod 777 /etc/sudoers
  cat > /etc/sudoers <<-EOF
Defaults   !visiblepw
Defaults    always_set_home
Defaults    match_group_by_gid
Defaults    always_query_group_plugin
Defaults    env_reset
Defaults    env_keep =  "COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS"
Defaults    env_keep += "MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE"
Defaults    env_keep += "LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES"
Defaults    env_keep += "LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE"
Defaults    env_keep += "LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"
Defaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin
root	ALL=(ALL) 	ALL
${newusername} ALL=(ALL) ALL
${newusername} ALL=NOPASSWD: ALL
#${newusername} ALL=NOPASSWD: /usr/libexec/openssh/sftp-server
Defaults:${newusername} !requiretty
%wheel	ALL=(ALL)	ALL
EOF
  chmod 440 /etc/sudoers
  cat > /etc/ssh/sshd_config <<-EOF
Port ${sshport}
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
SyslogFacility AUTHPRIV
PermitRootLogin no
AuthorizedKeysFile	.ssh/authorized_keys
PasswordAuthentication yes
ChallengeResponseAuthentication no
GSSAPIAuthentication yes
GSSAPICleanupCredentials no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 420
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS
Subsystem	sftp	/usr/libexec/openssh/sftp-server
EOF
  echo y | dnf install policycoreutils-python-utils
  semanage port -a -t ssh_port_t -p tcp ${sshport}
  semanage port -l | grep ssh
  systemctl restart sshd

  if [ "$mode" == "0" ];then
    start_menu 3          
  fi
  
}

start_menu(){
    clear
    if [ "$1" == "1" ];then
        green "=================================================="
        yteal " " "SSL Certificate has been successfully installed."
        green "=================================================="
    elif [ "$1" == "2" ];then
        green "=============================================="
        yteal " " "Successfully installed Docker."
        yteal " VPS IPv4:" $(curl -s ipv4.icanhazip.com)
        yteal " Protocol password:" $mainpasswd
        yteal " Trojan listen port:" "443"
        yteal " Trojan fallback port:" $fallbackport
        yteal " Shadowsocks listen port:" $ssport
        yteal " Shadowsocks encryption:" "chacha20-ietf-1305"
        green "=============================================="
    elif [ "$1" == "3" ];then
        green "======================================================="
        yteal " " "VPS security settings have been successfully updated."
        yellow " Root login has been disabled."
        yteal " SSH port has changed to:" $sshport
        yteal " Username of admin account:" $newusername
        yteal " Password of admin account:" $adminpasswd
        green "======================================================="
    else
        green "========================================="
        yteal "       System Requirement: " "CentOS8"
        green "========================================="
    fi
    echo
    green "  1. Install/Renew SSL Certificate"
    green "  2. Install Docker and Trojan/SS"
    yellow "  3. VPS Security Settings Update"
    red "  0. Exit Script"
    echo
    enter_promote " Enter a number:"
    read num
    echo
    case "$num" in
    1)
    cert
    ;;
    2)
    protocol_config
    install_docker
    ;;
    3)
    ssh_update_config
    ssh_update
    ;;
    0)
    exit 1
    ;;
    *)
    clear
    red "[Error] Please enter a valid number"
    sleep 1s
    start_menu
    ;;
    esac
}

[[ $EUID -ne 0 ]] && red "[Error] This script must be run as root!" && exit 1

mainpasswd="NULL"
fallbackport="NULL"
ssport="NULL"
# snellport="NULL"
sshport="NULL"
newusername="NULL"
adminpasswd="NULL"
containeropt="NULL"
mode=0

if [ $# -ne 0 ];then
    TEMP=`getopt -o "" -l protocol-passwd:,fallback-port:,ss-port:,ssh-port:,new-username:,admin-passwd:,container-opt: -- "$@"`
    eval set -- $TEMP
    while true ; do
            case "$1" in
                    --protocol-passwd) 
                        mainpasswd=$2;
                        shift 2;;
                    --fallback-port) 
                        fallbackport=$2;
                        shift 2;;
                    --ss-port) 
                        ssport=$2;
                        shift 2;;
                    --ssh-port) 
                        sshport=$2;
                        shift 2;;
                    --new-username) 
                        newusername=$2;
                        shift 2;;
                    --admin-passwd) 
                        adminpasswd=$2;
                        shift 2;;
                    --container-opt) 
                        containeropt=$2;
                        shift 2;;
                    --) 
                        shift ; 
                        break ;;
                    *) 
                        red "Invalid option.";
                        exit 1;;
            esac
    done
fi
if [ "$mainpasswd" != "NULL" ] && [ "$fallbackport" != "NULL" ] && [ "$ssport" != "NULL" ] && [ "$sshport" != "NULL" ] && [ "$newusername" != "NULL" ] && [ "$adminpasswd" != "NULL" ];then
    clear
    green "============================================================"
    yellow " Please confirm your VPS configuration:"
    yteal " VPS IPv4:" $(curl -s ipv4.icanhazip.com)
    yteal " Protocol password:" $mainpasswd
    yteal " Trojan listen port:" "443"
    yteal " Trojan fallback port:" $fallbackport
    yteal " Shadowsocks listen port:" $ssport
    yteal " Shadowsocks encryption:" "chacha20-ietf-1305"
    yteal " SSH port will be changed to:" $sshport
    yteal " Username of admin account:" $newusername
    yteal " Password of admin account:" $adminpasswd
    green "============================================================"
    echo
    enter_promote " Confirm(y/n):"
    read confirmation
    if [ "$confirmation" == "y" ] || [ "$confirmation" == "Y" ];then
        mode=1
        echo
        initialize
        cert
        if [ "$?" != "1" ];then
            install_docker
            ssh_update
            clear
            green "============================================================"
            green " Installation complete."
            yellow " Root login has been disabled."
            yteal " VPS IPv4:" $(curl -s ipv4.icanhazip.com)
            yteal " Protocol password:" $mainpasswd
            yteal " Trojan listen port:" "443"
            yteal " Trojan fallback port:" $fallbackport
            yteal " Shadowsocks listen port:" $ssport
            yteal " Shadowsocks encryption:" "chacha20-ietf-1305"
            yteal " SSH port has been changed to:" $sshport
            yteal " Username of admin account:" $newusername
            yteal " Password of admin account:" $adminpasswd
            green "============================================================"
        else
            exit 0
        fi
    else
        red " Exit"
        echo
        exit 0
    fi
else
    initialize
    start_menu
fi
