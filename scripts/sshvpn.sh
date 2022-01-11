#!/bin/bash

source /etc/os-release
export DEBIAN_FRONTEND=noninteractive

MYIP=$(wget -qO- icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";
country=MY
state=Kedah
locality=Gurun
organization=Cybertize
organizationalunit="Joekers VPN"
commonname=joekersvpn.com
email=admin@joekersvpn.com

# common password
wget -O /etc/pam.d/common-password "https://raw.githubusercontent.com/cybertize/joekers/default/files/password"
chmod +x /etc/pam.d/common-password

# Edu OVPN
wget -q -O /usr/local/bin/edu-ovpn https://raw.githubusercontent.com/cybertize/joekers/default/files/eduovpn.py
chmod +x /usr/local/bin/edu-ovpn

cat > /etc/systemd/system/edu-ovpn.service << END
[Unit]
Description=Python Edu Ovpn By Liufey
Documentation=https://liuuuuufey.my.id
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python -O /usr/local/bin/edu-ovpn 2082
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

systemctl daemon-reload &>/dev/null
systemctl enable edu-ovpn &>/dev/null
systemctl restart edu-ovpn &>/dev/null

cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

chmod +x /etc/rc.local
systemctl enable rc-local &>/dev/null
systemctl start rc-local.service &>/dev/null

ln -fs /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime

echo "/bin/false" >> /etc/shells
echo "/usr/bin/false" >> /etc/shells

echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

apt -y -qq update; apt -y -qq upgrade; apt -y -qq dist-upgrade

apt -y -qq install wget curl python ruby dos2unix dnsutils jq tcpdump dsniff grepcidr \
bzip2 gzip coreutils screen rsyslog net-tools zip unzip gnupg gnupg1 bc \
apt-transport-https build-essential dirmngr libxml-parser-perl git lsof \
openssl iptables iptables-persistent

apt -y -qq remove --purge ufw
apt -y -qq remove --purge firewalld
apt -y -qq remove --purge exim4
apt -y -qq remove --purge unscd
apt -y -qq remove --purge samba*
apt -y -qq remove --purge apache2*
apt -y -qq remove --purge bind9*
apt -y -qq remove --purge sendmail*

# install nginx
cd; apt -y install nginx
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/cybertize/joekers/default/files/nginx.conf"
mkdir -p /home/vps/public_html
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/cybertize/joekers/default/files/vps.conf"
/etc/init.d/nginx restart

# install badvpn
cd; wget -O /usr/bin/badvpn-udpgw "https://github.com/cybertize/joekers/raw/default/files/badvpn-udpgw64"
chmod +x /usr/bin/badvpn-udpgw
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500' /etc/rc.local
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 500

# install dropbear
apt -y -qq install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109 -p 69 -p 77"/g' /etc/default/dropbear

# banner /etc/issue.net
wget -O /etc/issue.net "https://raw.githubusercontent.com/cybertize/joekers/default/files/banner.conf"
echo "Banner /etc/issue.net" >>/etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear

# install squid
cd; apt -y install squid3
wget -O /etc/squid/squid.conf "https://raw.githubusercontent.com/cybertize/joekers/default/files/squid3.conf"
sed -i $MYIP2 /etc/squid/squid.conf

# install stunnel
apt -y -qq install stunnel4
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[edussl]
accept = 443
connect = 700

[dropbear]
accept = 222
connect = 127.0.0.1:22

[dropbear]
accept = 777
connect = 127.0.0.1:22

[openvpn]
accept = 442
connect = 127.0.0.1:1194
END

openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4

# Install OpenVPN dan Easy-RSA
apt -y -qq install openvpn easy-rsa
mkdir -p /etc/openvpn/pki/
mkdir -p /usr/lib/openvpn/
cd /etc/openvpn/
wget https://github.com/cybertize/joekers/raw/default/files/pki.zip
unzip pki.zip && rm -f pki.zip
chown -R root:root /etc/openvpn/pki/
cp /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /usr/lib/openvpn/openvpn-plugin-auth-pam.so
cd

cat > /etc/openvpn/client-tcp-1194.ovpn <<-END
client
dev tun
proto tcp
remote xxxxxxxxx 1194
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END
sed -i $MYIP2 /etc/openvpn/client-tcp-1194.ovpn;

cat > /etc/openvpn/client-udp-2200.ovpn <<-END
client
dev tun
proto udp
remote xxxxxxxxx 2200
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END
sed -i $MYIP2 /etc/openvpn/client-udp-2200.ovpn;

cat > /etc/openvpn/client-tcp-ssl.ovpn <<-END
client
dev tun
proto tcp
remote xxxxxxxxx 442
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END
sed -i $MYIP2 /etc/openvpn/client-tcp-ssl.ovpn;

echo '<ca>' >> /etc/openvpn/client-tcp-1194.ovpn
cat /etc/openvpn/pki/ca.crt >> /etc/openvpn/client-tcp-1194.ovpn
echo '</ca>' >> /etc/openvpn/client-tcp-1194.ovpn
cp /etc/openvpn/client-tcp-1194.ovpn /home/vps/public_html/client-tcp-1194.ovpn

echo '<ca>' >> /etc/openvpn/client-udp-2200.ovpn
cat /etc/openvpn/pki/ca.crt >> /etc/openvpn/client-udp-2200.ovpn
echo '</ca>' >> /etc/openvpn/client-udp-2200.ovpn
cp /etc/openvpn/client-udp-2200.ovpn /home/vps/public_html/client-udp-2200.ovpn

echo '<ca>' >> /etc/openvpn/client-tcp-ssl.ovpn
cat /etc/openvpn/pki/ca.crt >> /etc/openvpn/client-tcp-ssl.ovpn
echo '</ca>' >> /etc/openvpn/client-tcp-ssl.ovpn
cp /etc/openvpn/client-tcp-ssl.ovpn /home/vps/public_html/client-tcp-ssl.ovpn

# ipv4 forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf

iptables -t nat -I POSTROUTING -s 10.6.0.0/24 -o $NET -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.7.0.0/24 -o $NET -j MASQUERADE

# systemd openvpn
sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn
systemctl enable --now openvpn-server@server-tcp-1194
systemctl enable --now openvpn-server@server-udp-2200
/etc/init.d/openvpn start && systemctl enable openvpn

rm -f /root/vpn.sh

# install fail2ban
apt -y install fail2ban

# Instal DDOS Flate
if [ -d '/usr/local/ddos' ]; then
	echo "Please un-install the previous version first";exit 0
else
	mkdir /usr/local/ddos
fi

echo 'Installing DOS-Deflate 0.6';
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos

echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'

iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP

iptables-save > /etc/iptables.up.rules
chmod +x /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

# download script
cd /usr/bin
wget -O add-host "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/server/add-host.sh"
wget -O about "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/server/about.sh"
wget -O usernew "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/sshvpn/usernew.sh"
wget -O trial "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/sshvpn/trial.sh"
wget -O hapus "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/sshvpn/hapus.sh"
wget -O member "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/sshvpn/member.sh"
wget -O delete "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/sshvpn/delete.sh"
wget -O cek "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/sshvpn/cek.sh"
wget -O restart "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/service/restart.sh"
wget -O speedtest "https://github.com/cybertize/joekers/raw/default/plugins/server/speedtest_cli.py"
wget -O ram "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/server/ram.sh"
wget -O renew "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/sshvpn/renew.sh"
wget -O autokill "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/sshvpn/autokill.sh"
wget -O ceklim "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/sshvpn/ceklim.sh"
wget -O tendang "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/sshvpn/tendang.sh"
wget -O clear-log "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/server/clear-log.sh"
wget -O change-port "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/service/change.sh"
wget -O port-ovpn "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/service/port-ovpn.sh"
wget -O port-ssl "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/service/port-ssl.sh"
wget -O port-wg "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/service/port-wg.sh"
wget -O port-tr "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/service/port-tr.sh"
wget -O port-squid "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/service/port-squid.sh"
wget -O port-ws "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/service/port-ws.sh"
wget -O port-vless "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/service/port-vless.sh"
wget -O xp "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/sshvpn/xp.sh"
wget -O swap "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/server/swapkvm.sh"
wget -O menu "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/menu.sh"
wget -O ssh "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/update/ssh.sh"
wget -O ssssr "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/update/ssssr.sh"
wget -O trojaan "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/update/trojaan.sh"
wget -O v2raay "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/update/v2raay.sh"
wget -O wgr "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/update/wgr.sh"
wget -O vleess "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/update/vleess.sh"
wget -O bbr "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/server/bbr.sh"
wget -O bannerku "https://raw.githubusercontent.com/cybertize/joekers/default/files/bannerku"
wget -O update "https://raw.githubusercontent.com/cybertize/joekers/default/plugins/update.sh"
wget -O /usr/bin/user-limit https://raw.githubusercontent.com/cybertize/joekers/default/plugins/sshvpn/user-limit.sh && chmod +x /usr/bin/user-limit
chmod +x add-host; chmod +x usernew; chmod +x trial; chmod +x hapus; chmod +x member; chmod +x delete; chmod +x cek; chmod +x restart
chmod +x speedtest; chmod +x info; chmod +x ram; chmod +x renew; chmod +x about; chmod +x autokill; chmod +x ceklim; chmod +x tendang
chmod +x clear-log; chmod +x change-port; chmod +x port-ovpn; chmod +x port-ssl; chmod +x port-wg; chmod +x port-tr; chmod +x port-sstp
chmod +x port-squid; chmod +x port-ws; chmod +x port-vless; chmod +x wbmn; chmod +x xp; chmod +x swap; chmod +x menu; chmod +x l2tp
chmod +x ssh; chmod +x ssssr; chmod +x sstpp; chmod +x trojaan; chmod +x v2raay; chmod +x wgr; chmod +x vleess; chmod +x bbr
chmod +x bannerku; chmod +x update;
echo "0 5 * * * root clear-log" >> /etc/crontab
echo "0 0 * * * root xp" >> /etc/crontab

# finishing
cd
chown -R www-data:www-data /home/vps/public_html
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/cron restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/stunnel4 restart
/etc/init.d/squid restart
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 500
history -c
echo "unset HISTFILE" >> /etc/profile

cd
rm -f /root/key.pem
rm -f /root/cert.pem
rm -f /root/sshvpn.sh
