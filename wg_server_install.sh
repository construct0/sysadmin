#!/bin/bash
# set -x
set -e
set -o pipefail

WC="\033[1;36m"
WCE="\033[1;31m"
NC="\033[0m"
function println(){ builtin echo -e "${WC}${1}${NC}"; }
function printerr(){ builtin echo -e "${WCE}${1}${NC}"; }

# WireGuard VPN server setup script

# NL
# Aangepaste en uitgebreidere versie van het script dat gebruikt wordt door Hetzner. 
# Wijzigingen en uitbreidingen in een notendop:

# - standalone installatie script
# - controle van de DNS records indien een domeinnaam ingevoerd wordt
# - mogelijkheid om web interface beschikbaar te stellen via het IPv4 adres
#   - aanmaken van een self-signed SSL certificaat hiervoor
# - script kan opnieuw uitgevoerd worden
#   - geen "factory reset" van de VPS meer nodig voor het
#     - aanpassen van een vergeten web interface admin wachtwoord
#     - veranderen op welke manier de web interface bereikbaar is
#       - IPv4 > domeinnaam
#       - domeinnaam > IPv4
#       - domeinnaam > andere domeinnaam
# - script stopt met uitvoeren indien er onverwachte fouten voorkomen
# - default DNS van Google ipv Cloudflare
# - gebruik van Nginx
#   - configuratie van https server voor IPv4 web interface
#     - toepassen self-signed SSL certificaat
#     - reverse proxy
#     - HTTP redirect
#   - uitbreidbaar door gebruiker (bvb. reverse proxy voor alle soorten internetverkeer, niet alleen HTTPs) 
# - gebruik van Caddy voor domeinnaam web interface
#   - automatische aanvraag en hernieuwing van SSL certificaat met eenvoudigere configuratie dan met Nginx & certbot
# - installatie van miniupnpd
#   - inactief,
#   - indien later geconfigureerd door gebruiker
#     - laat dit VPN clients toe om extern IP adres te vragen aan de VPN server ipv. aan een derde partij


# EN
# This is a modified and extended version of the WireGuard setup script used by Hetzner.
# In this process WireGuard and the wireguard-ui web interface will be installed.

# Changes compared to original setup script:
# - standalone install script (but intended for Hetzner servers)
# - ensure domain points to the IPv4 and/or IPv6 of the server before continuing
# - make it possible to use the IPv4 address as host instead of requiring a mandatory domain name
#   - create self-signed SSL certificate for IPv4-based hosting
# - mistakes are correctable by re-running the script, not requiring server image rebuild or manual patch work
#   - changing/resetting admin password (name of user must be known and provided)
#   - changing web interface host (ipv4<->domain)
# - script exits on error instead of silently failing
# - google dns instead of cloudflare, personal preference
#   - IPv4 address based only by default, change the WGUI_DNS lines, or use the web interface to add it (recommended)
# - add use of nginx 
#   - to enable IPv4-based SSL certificate configuring
#       - (!) deletes default config
#   - to allow for reverse proxying of non-HTTP(s) traffic (requires custom config)
#   - nginx remains enabled if you decide to switch to domain-based with caddy
#       - (!) deletes wg-ipv4-access config 
# - limit use of caddy to domain-based setup
#   - allows for automatic SSL cert provisioning & renewing, a breeze compared to nginx and certbot for that purpose
# - added color to output statements for info and errors
# - install miniupnpd package
#   - (!) inactive/dormant unless configured and activated manually
#   - to allow VPN clients to request the public ip without having to rely on IP info providers (such as ip.me)


cat <<EOF
 _________________________________________________________________________
|                                                                         |
|   Welcome to the WireGuard configuration interface                      |
|                                                                         |
|   This is a modified and extended version of the WireGuard setup        |
|   script used by Hetzner.                                               |
|                                                                         |
|   Please wait for the necessary packages to be installed and default    |
|   configuration files to be created.                                    |
|                                                                         |
|   You will be prompted for configuration afterwards.                    |
|_________________________________________________________________________|
EOF

# Install apt packages
println "*** Installing apt packages, please wait.. This can take several minutes to complete."

# Allow the user to read the welcome message
sleep 5

export DEBIAN_FRONTEND=noninteractive
apt update &> /dev/null && apt install -y wireguard wireguard-tools miniupnpd nginx tcpdump traceroute git golang-go caddy &> /dev/null
unset DEBIAN_FRONTEND

# Install nvm, install nodejs 22, enable corepack
println "*** Installing nvm.."
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash &> /dev/null

# Make nvm available in the script
println "*** Loading nvm.."
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion

println "*** Installing nodejs 22.."
nvm install 22

println "*** Enabling corepack.."
corepack enable

# Init yarn and set version to 4.5.3
println "*** Installing latest stable version of yarn.."
corepack install -g yarn

println "*** Setting yarn to v4.5.3.."
yarn set version 4.5.3

# Install yarn
println "*** Installing yarn v4.5.3.."
yarn install 

# Clone wireguard-ui
cd /root/
println "*** Removing old wireguard-ui repository if it exists.."
rm -rf /root/wireguard-ui || true 

println "*** Cloning wireguard-ui repository.."
git clone https://github.com/ngoduykhanh/wireguard-ui

cd wireguard-ui

println "*** Upgrading repository to yarn 4.5.3.."
yarn install

# Set the repository to a known compatible state
println "*** Changing wireguard-ui repository HEAD.."
git reset --hard 2fdafd34ca6c8f7f1415a3a1d89498bb575a7171

# Ensure compatibility with yarn
println "*** Modifying wireguard-ui yarn command.."
sed -i 's/install --pure-lockfile --production/workspaces focus --production/g' ./prepare_assets.sh

# Prepare assets before compiling
println "*** Preparing static wireguard-ui assets.."
bash prepare_assets.sh

# Compile and and write the binary to file
println "*** Compiling wireguard-ui and writing to disk.."
go build -o /usr/local/bin/wireguard-ui

# Add init wireguard-ui configuration file
# The placeholders are replaced at the end of the script
println "*** Writing default configuration with temporary placeholders for wireguard-ui.."
echo -ne "# Default configuration for wireguard-ui.
# This file is loaded by the wireguard-ui systemd service.
#
# (!) Please note, that most of these settings have no affect after the first start of wireguard-ui.
# (!) After that, wireguard-ui stores these settings in its own db and you can change them through the UI (or manually in the db) only.

# Set this variable if you run wireguard-ui under a subpath of your reverse proxy virtual host.
#BASE_PATH=/wireguard

# The addresses where wireguard-ui should bind on.
#BIND_ADDRESS=0.0.0.0:80

# Used to encrypt the session cookies. Should be a random key, 32 characters long.
SESSION_SECRET=\$session_secret

# The login credentials for initial configuration.
WGUI_USERNAME=\$admin_username
WGUI_PASSWORD_HASH=\$admin_password_hash

# The default endpoint address used in the global settings.
WGUI_ENDPOINT_ADDRESS=\$domain

# The default DNS servers (comma-separated-list) used in the global settings.
WGUI_DNS=8.8.8.8,8.8.4.4

# Optional alternative: use IPv6 DNS addresses as well
# WGUI_DNS=8.8.8.8,8.8.4.4,2001:4860:4860:0:0:0:0:8888,2001:4860:4860:0:0:0:0:8844

# The default MTU used in the global settings.
# Theoretically, 1420 would be sufficient for Wireguard over IPv4 or IPv6. 1412 is safer when dealing with internet access over PPPoE.
# But because of all the broken WiFis out there that use tunnels but drop ICMP, we better leave a bit more headroom.
WGUI_MTU=1300

# The default persistent keepalive interval used in the global settings.
WGUI_PERSISTENT_KEEPALIVE=15

# The default firewall mark used in the global settings.
WGUI_FIREWALL_MARK=0xca6c

# The default routing table used in the global settings.
WGUI_TABLE=auto

# The default config file path used in the global settings.
WGUI_CONFIG_FILE_PATH=/etc/wireguard/wg0.conf

# The default log level.
WGUI_LOG_LEVEL=INFO

# The default interface addresses (comma-separated-list) used in the WireGuard server configuration.
WGUI_SERVER_INTERFACE_ADDRESSES=\$wg_interface_addresses

# The default server listen port used in the WireGuard server configuration.
WGUI_SERVER_LISTEN_PORT=51820

# The default post-up and post-down scripts used in the WireGuard server configuration.
WGUI_SERVER_POST_UP_SCRIPT=
WGUI_SERVER_POST_DOWN_SCRIPT=

# The default comma-separated-list of CIDRs for the 'Allowed IPs' field for new clients.
WGUI_DEFAULT_CLIENT_ALLOWED_IPS=0.0.0.0/0,::/0

# The default comma-separated-list of CIDRs for the 'Extra Allowed IPs' field for new clients.
WGUI_DEFAULT_CLIENT_EXTRA_ALLOWED_IPS=

# The default value for the 'Use Server DNS' checkbox for new clients.
WGUI_DEFAULT_CLIENT_USE_SERVER_DNS=true

# The default value for the 'Enable after creation' checkbox for new clients.
WGUI_DEFAULT_CLIENT_ENABLE_AFTER_CREATION=true

# You can configure further options, like email submission here.
# Please take a look into the wireguard-ui readme for further details: https://github.com/ngoduykhanh/wireguard-ui#email-configuration
" > /etc/default/wireguard-ui

# Add init caddy configuration file
# The placeholders are replaced at the end of the script
println "*** Writing default configuration with temporary placeholders for Caddy.."
echo -en "{
    # Used for automatic HTTPS
    email \$email
}

\$domain {
    reverse_proxy [::1]:5000
}" > /etc/caddy/Caddyfile

# Ensure the working directory for wireguard-ui exists
# If setup finishes and services are enabled this will contain the db with the configs used
println "*** Creating wireguard-ui working directory if it does not exist.."
mkdir -p /usr/local/share/wireguard-ui

DB_EXISTS=$(cd /usr/local/share/wireguard-ui && ls | wc -l)

# Add the systemd configuration profile
# It's started & enabled at the end of the script
println "*** Writing default systemd profile for wireguard-ui.."
echo -en "[Unit]
Description=WireGuard UI
Documentation=https://github.com/ngoduykhanh/wireguard-ui
After=network.target network-online.target
Requires=network-online.target
AssertFileIsExecutable=/usr/local/bin/wireguard-ui

[Service]
Type=simple
EnvironmentFile=/etc/default/wireguard-ui
WorkingDirectory=/usr/local/share/wireguard-ui
ExecStart=/usr/local/bin/wireguard-ui
Restart=on-failure
SyslogIdentifier=wireguard-ui

[Install]
WantedBy=multi-user.target
" > /etc/systemd/system/wireguard-ui.service


user_input(){
    println "*** Please enter the IPv4 address of this server ($host_ipv4_address) or a domain (e.g. wireguard.example.com) that points to the IPv4 and/or IPv6 address of this server." 
    while true
    do
        # This may occur when no IPv4 and IPv6 addresses are appointed and the user is managing through the web cloud console CLI 
        if [[ -z "$host_ipv4_address" && -z "$host_ipv6_address" ]]; then 
            printerr "*** Error: failed to determine both IPv4 and IPv6 host address, verifying provided IPv4 or the DNS resolution of domain name is not possible."
            printerr "*** Error: public hosting is not possible."
            exit 1;
        fi

        read -p ">>> Please enter the IPv4 address or domain: " hostchoice
        [ -z $hostchoice ] && continue

        if [ "$hostchoice" == "$host_ipv4_address" ]; then 
            unset domain
        else
            domain=$hostchoice
            unset hostchoice

            if nslookup "$domain" | grep -q "$host_ipv4_address"; then 
                println "*** Found matching IPv4 record for provided domain"
            elif nslookup "$domain" | grep -q "$host_ipv6_address"; then
                println "*** Found matching IPv6 record for provided domain"
            else 
                printerr "*** Error: domain provided ($domain) does not contain a DNS record for either\n*** IPv4 $host_ipv4_address \n*** or IPv6 $host_ipv6_address\n"
                unset domain
                continue
            fi 

            if [ "$domain" != "${domain/.clients.your-server.de/}" ]; then
                echo -en "\n"
                println "*** WARNING: Using *.clients.your-server.de domains is not recommended, because Let's Encrypt"
                println "*** will likely run into a rate limit and your VM will not be able to retrieve a TLS certificate."
                println "*** Please configure your own domain and enter it here."

                while true
                do
                    read -p ">>> Do you want to use this domain anyway? [y/N] " confirm
                    : ${confirm:="N"}

                    case $confirm in
                    [yY][eE][sS]|[yY] ) break 2;;
                    [nN][oO]|[nN] ) unset hostchoice domain; echo -en "\n"; continue 2;;
                    * ) echo ">>> Please type y or n.";;
                    esac
                done
            fi
        fi 

        PRESERVE_CREDS=0

        if [ "$DB_EXISTS" -gt 0 ]; then 
            while true
                do
                read -p ">>> Detected existing database, change password of an admin account? [y/N] " changepw
                : ${changepw:="N"}

                case $changepw in
                [yY][eE][sS]|[yY] ) PRESERVE_CREDS=0; break 2;;
                [nN][oO]|[nN] ) PRESERVE_CREDS=1; echo -en "\n"; break 2;;
                * ) echo ">>> Please type y or n.";;
                esac
            done
        fi

        break
    done

    if [ "$PRESERVE_CREDS" -eq 1 ]; then 
        println "*** An existing wireguard-ui database exists and user requested preservation of credentials.."

        # These are set to default values and will be written to the default wireguard-ui config file,
        # the credentials stored in the working directory (database) remain in effect, this merely ensures
        # continuation of the script
        username="admin"
        password="admin"
        password2="admin"
    else 
        echo -en "\n"

        echo ">>> Please enter the credentials for the user that is used to protect the management UI:"
        while [ -z $username ]
        do
            read -p ">>> Admin username: " username
        done

        while true
        do
            read -s -p ">>> Admin password: " password
            echo
            read -s -p ">>> Admin password (again): " password2
            echo
            [ "$password" = "$password2" ] && break || printerr ">>> Passwords are not the same, please try again."
        done
    fi

    if [ ! -z $domain ]; then
        echo -en "\n"
        echo ">>> Please enter an email address for Let's Encrypt notifications:"
        while [ -z $email ]
        do
            read -p ">>> Your email address: " email
        done
    fi
}

println "*** Generating wireguard-ui session secret.."
# Generate wireguard-ui session secret (16 bytes, 32 characters)
session_secret=$(openssl rand -hex 16)

# This address is not echo'd if it (doesn't) exist, to avoid confusion with the IPv4 address which
# may be used to serve the web interface with
println "*** Determining IPv6 subnet and public address.."

# Build the list of subnets to be used for WireGuard, depending on
# whether the VM has a IPv6 subnet assigned or not
#
# IPv4 is always enabled by default because this could still be useful
# for connecting to private networks
wg_interface_addresses=172.30.0.1/24
host_ipv6_subnet=$(ip addr show eth0 | grep "inet6\b.*global" | head -n1 | awk '{print $2}')
if [ ! -z $host_ipv6_subnet ]
then
  host_ipv6_address=$(echo $host_ipv6_subnet | cut -d/ -f1)
  wg_interface_addresses=$wg_interface_addresses,${host_ipv6_address%::1}:ac1e::1/120
  println "*** Adding IPv6 address to wireguard interface.."
fi

# Determine IPv4 address for interface eth0, which is the expected and default interface for a Hetzner server with a public IPv4 address attached
println "*** Determining public IPv4 address.."

host_ipv4_address=$(ifconfig eth0 | grep "inet " | head -n1 | awk '{print $2}')

if [[ $host_ipv4_address == *"error"* ]]; then 
    host_ipv4_address=
    printerr "*** Error: failed to determine public IPv4 address..\n\n"
else
    println "*** IPv4 address is $host_ipv4_address\n\n"
fi

cat <<EOF
 _________________________________________________________________________
|                                                                         |
|   Welcome to the WireGuard configuration interface                      |
|                                                                         |
|   This is a modified and extended version of the WireGuard setup        |
|   script used by Hetzner.                                               |
|                                                                         |
|   In this process WireGuard and the management UI will be installed     |
|   and set up accordingly.                                               |
|                                                                         |
|   Make a choice between IPv4-based or domain-based web access.          |
|   IPv4-based uses a self-signed certificate, domain-based obtains       |
|   a Let's Encrypt certificate.                                          |
|_________________________________________________________________________|
EOF

println "*** Please enter your details to set up your new WireGuard instance.\n"

# Request information from the user
user_input

# All but the password are visible and are to be checked by the user for correctness
while true
do
    echo -en "\n"
    read -p ">>> Is everything correct? [Y/n] " confirm
    : ${confirm:="Y"}

    # Continue if affirmative or reset the values and request information again
    case $confirm in
    [yY][eE][sS]|[yY] ) break;;
    [nN][oO]|[nN] ) unset hostchoice domain username password email; user_input;;
    * ) echo ">>> Please type y or n.";;
    esac
done

# If the database exists and the user requested password change for an account, delete the user account (nothing but role and credentials are defined in it)
# It's added again with the chosen password later in the script
if [ "$PRESERVE_CREDS" -eq 0 ]; then 
    if [ "$DB_EXISTS" -gt 0 ]; then 
        println "*** (!) An existing wireguard-ui database exists and user requested password change for account $username"
        println "*** (!) Deleting existing credentials.."

        EXISTING_USER_PATH=/usr/local/share/wireguard-ui/db/users/$username.json

        rm "$EXISTING_USER_PATH" &> /dev/null || true
    fi 
fi 

println "*** Configuring. Please wait..."

# Hash password and encode it again with base64 to be compatible with the format wireguard-ui requires
password_hash=$(caddy hash-password --algorithm bcrypt --plaintext "$password" | tr -d '\n' | base64 -w0)

# Populate the wireguard-ui default config
sed -i "s/\$session_secret/$session_secret/g" /etc/default/wireguard-ui
sed -i "s/\$admin_username/$username/g" /etc/default/wireguard-ui
sed -i "s/\$admin_password_hash/${password_hash//\//\\/}/g" /etc/default/wireguard-ui

if [ ! -z "$EXISTING_USER_PATH" ]; then 
    println "*** Creating admin user with username $username"

    echo -ne "{\"username\": \"$username\",\"password\": \"\",\"password_hash\": \"$password_hash\",\"admin\": true}" > $EXISTING_USER_PATH
fi 

sed -i "s/\$domain/$domain/g" /etc/default/wireguard-ui 

# Locally listen on port 5000, traffic is received from the nginx reverse proxy
sed -i 's/#BIND_ADDRESS=0.0.0.0:80/BIND_ADDRESS=[::1]:5000/g' /etc/default/wireguard-ui

# If an IPv4 address was provided
if [ ! -z $hostchoice ]; then
    # Domain is not used
    sed -i 's/WGUI_ENDPOINT_ADDRESS=/#WGUI_ENDPOINT_ADDRESS=/g' /etc/default/wireguard-ui
fi

sed -i "s/\$wg_interface_addresses/${wg_interface_addresses//\//\\/}/g" /etc/default/wireguard-ui

generate_selfsigned_ip_cert(){
    println "*** Generating self-signed SSL certificate for IP $host_ipv4_address"
    echo ""

openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -config <(cat <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = req_ext
prompt = no

[req_distinguished_name]
CN = $host_ipv4_address

[req_ext]
subjectAltName = @alt_names

[alt_names]
IP.1 = $host_ipv4_address
EOF
)
openssl x509 -req -in server.csr -signkey server.key -out server.crt -days 36500 -extensions req_ext -extfile <(cat <<EOF
[req_ext]
subjectAltName = @alt_names

[alt_names]
IP.1 = $host_ipv4_address
EOF
)

    echo ""
    echo ""
    println "*** (!) Extracting sha256 certificate fingerprint, please verify it corresponds\n*** (!) with the fingerprint of the certificate when accessing the VPN web interface."
    println "*** (!) This is the only way ownership and authenticity can be guarantueed.\n*** (!) The certificate is valid for 100 years.\n*** (!) Setting up a domain name for your instance is highly recommended."
    echo ""

    openssl x509 -in server.crt -noout -fingerprint -sha256
}

if [ ! -z $domain ]; then 
    println "*** Setting up domain-based web interface.."
    println "*** Removing IP-based config file.."
    # Nginx is not used for a domain-based setup
    # Delete the IP-based configuration if it exists
    rm /etc/nginx/sites-enabled/wg-ipv4-access &> /dev/null || true

    # Reload nginx if it's running
    systemctl reload nginx.service &> /dev/null || true

    println "*** Configuring domain-based config file.."
    # Populate the caddy config
    sed -i "s/\$domain/$domain/g" /etc/caddy/Caddyfile
    sed -i "s/\$email/$email/g" /etc/caddy/Caddyfile

    # Start wireguard-ui and caddy
    println "*** Adding wireguard-ui & caddy to startup.."
    systemctl enable wireguard-ui.service caddy.service &> /dev/null

    println "*** Reloading wireguard-ui & caddy.."
    systemctl stop wireguard-ui.service &> /dev/null
    systemctl start wireguard-ui.service &> /dev/null
    systemctl reload caddy.service &> /dev/null || systemctl start caddy.service &> /dev/null
else 
    println "*** Setting up IP-based web interface.."
    println "*** Stopping caddy & removing from startup.."

    # Caddy is not used for an IP-based setup
    # We're making sure it's not running and removing it from startup
    systemctl stop caddy.service &> /dev/null
    systemctl disable caddy.service &> /dev/null

    println "*** Removing default nginx config file.."
    # Delete the default nginx configuration if it exists
    rm /etc/nginx/sites-enabled/default &> /dev/null || true

    println "*** Writing nginx config file.."
    # Add the reverse proxy
    echo -en "# Redirect HTTP traffic to HTTPS
server {
    listen                  80;
    listen                  [::]:80;

    return 307              https://\$host\$request_uri;
}

# Reverse proxy, port 5000 is used by wireguard-ui
server {
    listen                  443 ssl;
    listen                  [::]:443 ssl;

    ssl_certificate         /root/wireguard-ui-certs/server.crt;
    ssl_certificate_key     /root/wireguard-ui-certs/server.key;

    location / {
        proxy_pass          \"http://localhost:5000\";
    }
}" > /etc/nginx/sites-enabled/wg-ipv4-access

    println "*** Creating directory for SSL certificates.."
    mkdir -p /root/wireguard-ui-certs && cd /root/wireguard-ui-certs


    generate_selfsigned_ip_cert

    # Start wireguard-ui and nginx
    println "*** Adding wireguard-ui and nginx to startup.."
    systemctl enable nginx.service wireguard-ui.service &> /dev/null

    println "*** Reloading wireguard-ui and nginx.."
    systemctl reload nginx.service &> /dev/null || systemctl start nginx.service &> /dev/null
    systemctl stop wireguard-ui.service &> /dev/null
    systemctl start wireguard-ui.service &> /dev/null
fi

println "*** Awaiting wireguard config creation by wireguard-ui.."
# Wait until wireguard-ui generated the WireGuard config, if it already exists it is preserved
until [ -f /etc/wireguard/wg0.conf ]
do
  sleep 0.1
done
sleep 0.1

# Start wireguard and watch for config changes
println "*** Adding wireguard to startup.."
systemctl enable wg-quick@wg0.service &> /dev/null

# Reloading wireguard 
println "*** Reloading wireguard.."
systemctl reload wg-quick@wg0.service &>/dev/null || systemctl start wg-quick@wg0.service &> /dev/null

println "*** Adding wireguard watcher to startup.."
systemctl enable wg-quick-watcher@wg0.{path,service} &> /dev/null

println "*** Reloading wireguard watcher.."
systemctl reload wg-quick-watcher@wg0.{path,service} &>/dev/null || systemctl start wg-quick-watcher@wg0.{path,service} &> /dev/null

# Enable the firewall
println "*** Adding nftables firewall to startup.."
systemctl enable nftables.service &> /dev/null

println "*** Reloading nftables.."
systemctl reload nftables.service &> /dev/null || systemctl start nftables.service &> /dev/null

# Enable IP forwarding
println "*** Enabling IP forwarding.."
sed -i '/net.ipv4.ip_forward=1/s/^#//g' /etc/sysctl.conf
sed -i '/net.ipv6.conf.all.forwarding=1/s/^#//g' /etc/sysctl.conf
sysctl -p &> /dev/null

echo -en "\n\n"
println "*** The installation is complete and WireGuard should be ready to use."

if [ ! -z $domain ]; then 
    println "*** Please go to https://$domain and log in with the user \"$username\" and your password to configure WireGuard clients."
else 
    println "*** Please go to http://$hostchoice and log in with the user \"$username\" and your password to configure WireGuard clients."
fi

echo -en "\n"

# todo
# echo -en "system_uptime=no
# uuid=1ed759ff-3493-4b57-a691-b5193111e8f2
# force_igd_desc_v1=no
# ext_ifname=eth0
# listening_ip=wg0

# # No UPnP for all ports, the daemon is added to enable external-ip resolving client-side
# deny 0-65535 0.0.0.0/0 0-65535" > /etc/miniupnpd/miniupnpd.conf 

# systemctl enable miniupnpd
# systemctl start miniupnpd
