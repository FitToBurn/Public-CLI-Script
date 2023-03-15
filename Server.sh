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

firewall_settings(){
    ufw disable
    systemctl stop firewalld.service
    systemctl disable firewalld.service
    sudo iptables -F
}

cert(){
    real_addr=`ping ${domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
    local_addr=`curl ipv4.icanhazip.com`
    if [ "$mode" == "UC" ] || [ $real_addr == $local_addr ]; then
        green "==============================="
        green "Domain name resolves correctly."
        green "==============================="

        apt-get update
        apt-get install -y unzip zip curl tar nginx
        #apt-get install -y libseccomp-devel
        systemctl enable nginx.service

        #设置伪装站
        rm -rf /var/www/html/*
        cd /var/www/html/
        wget https://github.com/atrandys/v2ray-ws-tls/raw/master/web.zip
            unzip web.zip
        systemctl restart nginx.service
        if [ "$mode" != "UC" ];then
            if test -s /usr/src/cert/fullchain.cer; then
                return 0
            fi
        fi
        mkdir /usr/src/cert
        rm -f /usr/src/cert/private.key
        rm -f /usr/src/cert/fullchain.cer
        curl https://get.acme.sh | sh
        ~/.acme.sh/acme.sh  --debug --set-default-ca --server letsencrypt
        ~/.acme.sh/acme.sh  --debug --issue  -d $domain  --webroot /var/www/html/
        ~/.acme.sh/acme.sh  --debug --installcert  -d  $domain   \
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
    # Portainer
    # SubConverter
    # downloader
    # V2Ray
    # HatH

    # Portainer
    docker pull portainer/portainer-ce:latest
    docker volume create portainer_data

    docker run -d \
    -p $portainer_port:9443 -p 8000:8000 \
    --name=portainer \
    --restart=always \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /var/lib/docker/volumes/portainer_data/:/data/ \
    -v /usr/src/cert:/cert \
    portainer/portainer-ce --sslcert /cert/fullchain.cer --sslkey /cert/private.key

    cat > /etc/nginx/nginx.conf << EOF
user nobody nogroup;
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
        root         /var/www/html/;

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
EOF

    if [ "$openai" != "NULL" ];then
    head -c -1 << EOF | cat >> /etc/nginx/nginx.conf
    server {
        listen $openai_port ssl http2;
        server_name  _;
        gzip on;
        ssl_certificate /usr/src/cert/fullchain.cer;
        ssl_certificate_key /usr/src/cert/private.key;

        location /$openai_pass/ {
            proxy_pass https://api.openai.com/;
            proxy_set_header  Host                api.openai.com;
            proxy_set_header  X-Real-IP           \$remote_addr;
        }
    } 
EOF
    fi

    if [ "$mode" == "MS" ];then
    head -c -1 << EOF | cat >> /etc/nginx/nginx.conf
    server {
        listen $subconverter_port ssl http2;
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
        listen $downloader_port ssl http2;
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
EOF
    fi
    cat >> /etc/nginx/nginx.conf << EOF

}
EOF
    
    nginx -s reload
    
    if [ "$mode" == "MS" ];then

        # SubConverter
        docker pull tindy2013/subconverter:latest

        docker run -d \
        --name=subconverter \
        --restart=always \
        -p 25500:25500 \
        tindy2013/subconverter

        # downloader
        docker pull bigdaddywrangler/downloader
        docker volume create downloader
        generate_json "nodes"
        generate_json "keypair"
        generate_json "rules"
        generate_json "airport"

        docker run -d \
        --name=downloader \
        --restart=always \
        -v /var/lib/docker/volumes/downloader/nodes.json:/usr/bin/nodes.json \
        -v /var/lib/docker/volumes/downloader/keypair.json:/usr/bin/keypair.json \
        -v /var/lib/docker/volumes/downloader/rules.json:/usr/bin/rules.json \
        -v /var/lib/docker/volumes/downloader/airport.json:/usr/bin/airport.json \
        -p 25501:25501 \
        bigdaddywrangler/downloader:latest

    fi

    if [ "$v2fly" != "NULL" ];then
        #V2fly
        docker pull v2fly/v2fly-core:latest
        docker volume create v2fly_config
        cat > /var/lib/docker/volumes/v2fly_config/config.json << EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
EOF
        if [ "$trojan_protocol" == "1" ];then
        head -c -1 << EOF | cat >> /var/lib/docker/volumes/v2fly_config/config.json
    {
      "listen": "0.0.0.0",
      "port": 443, 
      "protocol": "trojan",
      "settings": {
        "clients":[{"password": "$v2fly_passwd"}],
        "fallbacks": [{"dest": 80}]
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
EOF
        fi
        cat >> /var/lib/docker/volumes/v2fly_config/config.json << EOF

    {
      "listen": "0.0.0.0",
      "port": $ss_port, 
      "protocol": "shadowsocks",
      "settings":{
          "method": "chacha20-ietf-poly1305",
          "ota": false, 
          "password": "$v2fly_passwd"
      }
    }
  ],
  "outbounds": [{ 
    "protocol": "freedom"
  }]
}
EOF
        docker run -d \
        --network=host \
        --name=v2fly \
        --restart=always \
        -v /var/lib/docker/volumes/v2fly_config/config.json:/etc/v2ray/config.json \
        -v /usr/src/cert:/cert \
        v2fly/v2fly-core \
        run -c /etc/v2ray/config.json
    fi
    
    if [ "$hath" != "NULL" ];then
    
        #HatH
        docker pull ghcr.io/disappear9/hentaiathome:latest
        docker run -d \
        --name HatH \
        --restart=always \
        -p $hath_port:$hath_port \
        -v /usr/HatH:/hath/data \
        -v /usr/HatH_download:/hath/download \
        -e HatH_KEY="$hath_id_key" \
        -e HatH_ARGS="--cache-dir=/hath/data/cache --data-dir=/hath/data/data --download-dir=/hath/download --log-dir=/hath/data/log --temp-dir=/hath/data/temp --disable_logging" \
        ghcr.io/disappear9/hentaiathome:latest

    fi

}

ssh_update(){

    useradd -m ${admin_username}
    chpasswd <<< "${admin_username}:${admin_passwd}"

    chmod 777 /etc/sudoers
    cat > /etc/sudoers << EOF
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
${admin_username} ALL=(ALL) ALL
${admin_username} ALL=NOPASSWD: ALL
#${admin_username} ALL=NOPASSWD: /usr/libexec/openssh/sftp-server
Defaults:${admin_username} !requiretty
%wheel	ALL=(ALL)	ALL
EOF
    chmod 440 /etc/sudoers
    cat > /etc/ssh/sshd_config << EOF
Port ${ssh_port}
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
Subsystem	sftp	sudo -n true && sudo -n /usr/lib/openssh/sftp-server || /usr/lib/openssh/sftp-server
EOF
    echo y | apt install policycoreutils-python-utils
    semanage port -a -t ssh_port_t -p tcp ${ssh_port}
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
                "name":"${arrtemp[2]}",
                "protocol":"${arrtemp[0]}",
                "server":"${arrtemp[1]}"
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

    elif [ "$1" == "airport" ];then
        arr=(`echo $airport | tr ';' ' '`)
        cat > /var/lib/docker/volumes/downloader/airport.json << EOF
    {
        "airport":["${arr[0]}"]
    }
EOF

    fi

}

#=============================================================================
#=============================================================================
#=============================================================================
#=============================================================================
#===========================Beginning of the script===========================
#=============================================================================
#=============================================================================
#=============================================================================
#=============================================================================

[[ $EUID -ne 0 ]] && red "[Error] This script must be run as root!" && exit 1

domain="NULL"
mode="NULL"

nodes="NULL"
keypair="NULL"
rules="NULL"
airport="NULL"

ssh="NULL"
ssh_port="NULL"
admin_username="NULL"
admin_passwd="NULL"

hath="NULL"
hath_port="NULL"
hath_id_key="NULL"

v2fly="NULL"
ss_port="NULL"
v2fly_passwd="NULL"
trojan_protocol="NULL"

ports="NULL"
portainer_port="NULL"
subconverter_port="NULL"
downloader_port="NULL"

openai="NULL"
openai_port="NULL"
openai_pass="NULL"

if [ $# -ne 0 ];then
    TEMP=`getopt -o "" -l mode:,domain:,ssh:,ports:,v2fly:,hath:,openai:,nodes:,keypair:,rules:,airport:, -- "$@"`
    eval set -- $TEMP
    while true ; do
            case "$1" in
                    --mode) 
                        mode=$2;
                        shift 2;;
                    --domain) 
                        domain=$2;
                        shift 2;;
                    --ssh) 
                        ssh=$2;
                        shift 2;;
                    --ports) 
                        ports=$2;
                        shift 2;;
                    --v2fly) 
                        v2fly=$2;
                        shift 2;;
                    --hath) 
                        hath=$2;
                        shift 2;;
                    --openai) 
                        openai=$2;
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
                    --airport) 
                        airport=$2;
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

clear

# ServerInitialization
if [ "$mode" == "MS" ] || [ "$mode" == "NS" ];then

    if [ "$mode" == "MS" ];then
        if [ "$ssh" == "NULL" ] || [ "$domain" == "NULL" ] || [ "$ports" == "NULL" ] || [ "$nodes" == "NULL" ] || [ "$keypair" == "NULL" ] || [ "$rules" == "NULL" ] || [ "$airport" == "NULL" ];then
            red "Invalid option.";
            exit 1
        fi
    fi
    if [ "$mode" == "NS" ];then
        if [ "$ssh" == "NULL" ] || [ "$domain" == "NULL" ] || [ "$ports" == "NULL" ];then
            red "Invalid option.";
            exit 1
        fi
    fi
    
    arr=(`echo $ssh | tr ';' ' '`)
    ssh_port=${arr[0]}
    admin_username=${arr[1]}
    admin_passwd=${arr[2]}

    arr=(`echo $v2fly | tr ';' ' '`)
    ss_port=${arr[0]}
    v2fly_passwd=${arr[1]}
    trojan_protocol=${arr[2]}

    arr=(`echo $hath | tr ';' ' '`)
    hath_port=${arr[0]}
    hath_id_key=${arr[1]}

    arr=(`echo $ports | tr ';' ' '`)
    portainer_port=${arr[0]}
    subconverter_port=${arr[1]}
    downloader_port=${arr[2]}

    arr=(`echo $openai | tr ';' ' '`)
    openai_port=${arr[0]}
    openai_pass=${arr[1]}

    green "============================================================"
    if [ "$mode" == "MS" ];then
        yellow " Main Server Configuration:"
    fi
    if [ "$mode" == "NS" ];then
        yellow " Node Server Configuration:"
    fi
    yteal " VPS Domain:" $domain
    yteal " VPS IPv4:" $(curl -s ipv4.icanhazip.com)
    green "============================================================"
    echo
    enter_promote " Confirm(y/n):"
    read confirmation
    if [ "$confirmation" == "y" ] || [ "$confirmation" == "Y" ];then
        echo
        firewall_settings
        cert
        if [ "$?" != "1" ];then
            install_docker
            ssh_update
            clear
            green "============================================================"
            if [ "$mode" == "MS" ];then
                yellow " Main Server Installation Complete."
            fi
            if [ "$mode" == "NS" ];then
                yellow " Node Server Installation Complete."
            fi
            yteal " VPS Domain:" $domain
            yteal " VPS IPv4:" $(curl -s ipv4.icanhazip.com)
            green "============================================================"
        else
            exit 0
        fi
    else
        red " Exit"
        echo
        exit 0
    fi

# UpdateCert
elif [ "$mode" == "UC" ];then
    if [ "$domain" == "NULL" ];then
        red "Invalid option.";
        exit 1
    fi
    cert
    if [ "$?" != "1" ];then
        systemctl restart docker
        green "=================================================="
        yteal " " "SSL Certificate has been successfully Updated."
        green "=================================================="
    else
        exit 0
    fi

# #UpdateSub
elif [ "$mode" == "US" ];then
    if [ "$nodes" == "NULL" ] && [ "$keypair" == "NULL" ] && [ "$rules" == "NULL" ] && [ "$airport" == "NULL" ];then
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
    if [ "$airport" != "NULL" ];then
        generate_json "airport"
    fi
    docker restart downloader
    green "==================================================="
    yteal " " "Subscription info has been successfully Updated."
    green "==================================================="
    exit 0
fi
