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
        rm -f /usr/src/cert/private.key
        rm -f /usr/src/cert/fullchain.cer
        curl https://get.acme.sh | sh
        ~/.acme.sh/acme.sh  --set-default-ca --server letsencrypt
        ~/.acme.sh/acme.sh  --issue  -d $your_domain  --webroot /usr/share/nginx/html/
        ~/.acme.sh/acme.sh  --installcert  -d  $your_domain   \
            --key-file   /usr/src/cert/private.key \
            --fullchain-file /usr/src/cert/fullchain.cer \
            --reloadcmd  "systemctl force-reload  nginx.service"
        if test -s /usr/src/cert/fullchain.cer; then
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

install_docker(){
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    systemctl start docker
    systemctl enable docker
    systemctl enable containerd

    ###===Current List===###
    #~ Portainer
    #~ SubConverter
    #~ livemonitor
    #~ downloader
    #+ V2Ray

    if [ "$mode" == "MainServerInitialization" ];then
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
        docker volume create downloader
        generate_json "nodes"
        generate_json "keypair"
        generate_json "rules"
        generate_json "pubnodes"
        docker run -d --name=downloader --restart=always -v /var/lib/docker/volumes/downloader/nodes.json:/usr/bin/nodes.json -v /var/lib/docker/volumes/downloader/keypair.json:/usr/bin/keypair.json -v /var/lib/docker/volumes/downloader/rules.json:/usr/bin/rules.json -v /var/lib/docker/volumes/downloader/pubnodes.json:/usr/bin/pubnodes.json -p 25501:25501 bigdaddywrangler/downloader:latest
        
        nginx -s reload
    fi

    #V2fly
    docker pull v2fly/v2fly-core:latest
    docker volume create v2fly_config
	head -c -1 << EOF | cat > /var/lib/docker/volumes/v2fly_config/config.json
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
EOF
    if [ "$pubpasswd" != "NULL" ];then
        echo "," | cat >> /var/lib/docker/volumes/v2fly_config/config.json
        cat >> /var/lib/docker/volumes/v2fly_config/config.json <<-EOF
    {
      "listen": "0.0.0.0",
      "port": $((${ssport}+5)), 
      "protocol": "shadowsocks",
      "settings":{
          "method": "chacha20-ietf-poly1305",
          "ota": false, 
          "password": "$pubpasswd"
      }
    }
EOF
    else
        echo "" | cat >> /var/lib/docker/volumes/v2fly_config/config.json
    fi
    cat >> /var/lib/docker/volumes/v2fly_config/config.json <<-EOF
  ],
  "outbounds": [{ 
    "protocol": "freedom"
  }]
}
EOF
    docker run -d --network=host --name=v2fly --restart=always -v /var/lib/docker/volumes/v2fly_config/config.json:/etc/v2ray/config.json -v /usr/src/cert:/cert v2fly/v2fly-core
    
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
Subsystem	sftp	sudo -n true && sudo -n /usr/libexec/openssh/sftp-server || /usr/libexec/openssh/sftp-server
EOF
  echo y | dnf install policycoreutils-python-utils
  semanage port -a -t ssh_port_t -p tcp ${sshport}
  semanage port -l | grep ssh
  systemctl restart sshd
  
}

generate_json(){
if [ "$1" == "nodes" ];then
    arr=(`echo $nodes | tr ';' ' '`)
    cat > /var/lib/docker/volumes/downloader/nodes.json << EOF
    {
        "nodes":[
EOF
    
    for ((i=0;i<${#arr[@]};i++))
    do
        arrtemp=(`echo ${arr[$i]} | tr ',' ' '`)
        head -c -1 << EOF | cat >> /var/lib/docker/volumes/downloader/nodes.json
            {
                "name":"${arrtemp[4]}",
                "protocol":"${arrtemp[0]}",
                "server":"${arrtemp[1]}",
                "port":${arrtemp[2]},
                "password":"${arrtemp[3]}"
            }
EOF
        if [ "$i" != "$((${#arr[@]}-1))" ];then
            echo "," | cat >> /var/lib/docker/volumes/downloader/nodes.json
        fi
    done
    
    cat >> /var/lib/docker/volumes/downloader/nodes.json << EOF
    
        ]
    }
EOF

elif [ "$1" == "pubnodes" ];then
    arr=(`echo $pubnodes | tr ';' ' '`)
    cat > /var/lib/docker/volumes/downloader/pubnodes.json << EOF
    {
        "nodes":[
EOF
    
    for ((i=0;i<${#arr[@]};i++))
    do
        arrtemp=(`echo ${arr[$i]} | tr ',' ' '`)
        head -c -1 << EOF | cat >> /var/lib/docker/volumes/downloader/pubnodes.json
            {
                "name":"${arrtemp[4]}",
                "protocol":"${arrtemp[0]}",
                "server":"${arrtemp[1]}",
                "port":${arrtemp[2]},
                "password":"${arrtemp[3]}"
            }
EOF
        if [ "$i" != "$((${#arr[@]}-1))" ];then
            echo "," | cat >> /var/lib/docker/volumes/downloader/pubnodes.json
        fi
    done
    
    cat >> /var/lib/docker/volumes/downloader/pubnodes.json << EOF
    
        ]
    }
EOF

elif [ "$1" == "rules" ];then
    arr=(`echo $rules | tr ';' ' '`)
    cat > /var/lib/docker/volumes/downloader/rules.json << EOF
    {
        "rules":[
EOF
    
    for ((i=0;i<${#arr[@]};i++))
    do
        head -c -1 << EOF | cat >> /var/lib/docker/volumes/downloader/rules.json
            "${arr[$i]}"
EOF
        if [ "$i" != "$((${#arr[@]}-1))" ];then
            echo "," | cat >> /var/lib/docker/volumes/downloader/rules.json
        fi
    done
    
    cat >> /var/lib/docker/volumes/downloader/rules.json << EOF
    
        ]
    }
EOF

elif [ "$1" == "keypair" ];then
    arr=(`echo $keypair | tr ';' ' '`)
    cat > /var/lib/docker/volumes/downloader/keypair.json << EOF
    {
        "keys":["${arr[0]}","${arr[1]}"]
    }
EOF

fi
}



[[ $EUID -ne 0 ]] && red "[Error] This script must be run as root!" && exit 1

mainpasswd="NULL"
fallbackport="NULL"
ssport="NULL"
sshport="NULL"
newusername="NULL"
adminpasswd="NULL"

mode="NULL"
nodes="NULL"
pubnodes="NULL"
keypair="NULL"
rules="NULL"
pubpasswd="NULL"

if [ $# -ne 0 ];then
    TEMP=`getopt -o "" -l protocol-passwd:,fallback-port:,ss-port:,ssh-port:,new-username:,admin-passwd:,mode-opt:,nodes:,keypair:,rules:,pubnodes:,pubpasswd:, -- "$@"`
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
                    --mode-opt) 
                        mode=$2;
                        shift 2;;
                    --nodes) 
                        nodes=$2;
                        shift 2;;
                    --keypair) 
                        keypair=$2;
                        shift 2;;
                    --rules) 
                        rules=$2;
                        shift 2;;
                    --pubnodes) 
                        pubnodes=$2;
                        shift 2;;
                    --pubpasswd) 
                        pubpasswd=$2;
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
if [ "$mode" == "MainServerInitialization" ] || [ "$mode" == "ServerInitialization" ];then
    clear
    if [ "$mainpasswd" == "NULL" ] || [ "$fallbackport" == "NULL" ] || [ "$ssport" == "NULL" ] || [ "$sshport" == "NULL" ] || [ "$newusername" == "NULL" ] || [ "$adminpasswd" == "NULL" ];then
        red "Invalid option.";
        exit 1
    elif [ "$mode" == "MainServerInitialization" ];then
        yellow " Main Server"
        if [ "$nodes" == "NULL" ] || [ "$keypair" == "NULL" ] || [ "$rules" == "NULL" ] || [ "$pubnodes" == "NULL" ];then
            red "Invalid option.";
            exit 1
        fi
    fi
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
elif [ "$mode" == "UpdateCert" ];then
    clear
    cert
    if [ "$?" != "1" ];then
        systemctl restart docker
        green "=================================================="
        yteal " " "SSL Certificate has been successfully Updated."
        green "=================================================="
    else
        exit 0
    fi
elif [ "$mode" == "UpdateSub" ];then
    clear
    if [ "$nodes" == "NULL" ] && [ "$keypair" == "NULL" ] && [ "$rules" == "NULL" ] && [ "$pubnodes" == "NULL" ];then
        red "Invalid option.";
        exit 1
    fi
    if [ "$nodes" != "NULL" ];then
        generate_json "nodes"
    fi
    if [ "$keypair" != "NULL" ];then
        generate_json "keypair"
    fi
    if [ "$rules" != "NULL" ];then
        generate_json "rules"
    fi
    if [ "$pubnodes" != "NULL" ];then
        generate_json "pubnodes"
    fi
    green "==================================================="
    yteal " " "Subscription info has been successfully Updated."
    green "==================================================="
    exit 0
fi
