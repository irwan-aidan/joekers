#!/bin/bash
clear

if [ "${EUID}" -ne 0 ]; then
	echo "You need to run this script as root"; exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
	echo "OpenVZ is not supported"; exit 1
fi
if [ -f "/etc/v2ray/domain" ]; then
	echo "Script Already Installed"; exit 0
fi

touch /root/domain;
mkdir /var/lib/premium-script;
echo "IP=" >> /var/lib/premium-script/ipvps.conf

apt -qq update; apt -y -qq upgrade;
wget -q https://raw.githubusercontent.com/cybertize/joekers/default/scripts/cf.sh && bash cf.sh

wget -q https://raw.githubusercontent.com/cybertize/joekers/default/scripts/sshvpn.sh && screen -S sshvpn bash sshvpn.sh
wget -q https://raw.githubusercontent.com/cybertize/joekers/default/scripts/weleh.sh && screen -S weleh bash weleh.sh
wget -q https://raw.githubusercontent.com/cybertize/joekers/default/scripts/ssr.sh && screen -S ssr bash ssr.sh
wget -q https://raw.githubusercontent.com/cybertize/joekers/default/scripts/libev.sh && screen -S ss bash libeb.sh
wget -q https://raw.githubusercontent.com/cybertize/joekers/default/scripts/wireguard.sh && screen -S wg bash wireguard.sh
wget -q https://raw.githubusercontent.com/cybertize/joekers/default/scripts/v2ray.sh && screen -S v2ray bash v2ray.sh

wget -q https://raw.githubusercontent.com/cybertize/joekers/default/scripts/setbr.sh && bash setbr.sh

rm -f /root/sshvpn.sh
rm -f /root/weleh.sh
rm -f /root/wireguard.sh
rm -f /root/libev.sh
rm -f /root/ssr.sh
rm -f /root/setbr.sh

cat << EOF > /etc/systemd/system/autosett.service
[Unit]
Description=autosetting
Documentation=https://joekersvpn.com

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/set.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable autosett
wget -O /etc/set.sh "https://raw.githubusercontent.com/anisakansa/project1/main/set.sh"
chmod +x /etc/set.sh
echo " "
echo "Installation has been completed!!"
echo " "
echo "================ SCRIPT LOGGER ================" | tee -a log-install.txt
echo "Service & Port" | tee -a log-install.txt
echo "  OpenSSH : 22" | tee -a log-install.txt
echo "  Dropbear : 109, 143" | tee -a log-install.txt
echo "  OpenVPN : TCP 1194, UDP 2200, SSL 442"  | tee -a log-install.txt
echo "  Stunnel : 222, 777" | tee -a log-install.txt
echo "  Squid : 3128, 8080" | tee -a log-install.txt
echo "  Badvpn : 7100, 7200, 7300" | tee -a log-install.txt
echo "  SS-OBFS TLS : 2443-2543" | tee -a log-install.txt
echo "  SS-OBFS HTTP : 3443-3543" | tee -a log-install.txt
echo "  Shadowsocks-R : 1443-1543" | tee -a log-install.txt
echo "  Vmess TLS : 8443" | tee -a log-install.txt
echo "  Vmess None TLS : 80" | tee -a log-install.txt
echo "  Vless TLS : 2083" | tee -a log-install.txt
echo "  Vless None TLS : 8880" | tee -a log-install.txt
echo "  Trojan : 2087" | tee -a log-install.txt
echo "  Wireguard : 7070" | tee -a log-install.txt
echo "  Nginx : 81" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Server Information & Other Features" | tee -a log-install.txt
echo "	Timezone : Kuala_Lumpur (GMT 0800)" | tee -a log-install.txt
echo "	Fail2Ban : [ON]" | tee -a log-install.txt
echo "	DDoS Deflate : [ON]" | tee -a log-install.txt
echo "	IPtables : [ON]" | tee -a log-install.txt
echo "	Auto-Reboot : [ON]" | tee -a log-install.txt
echo "	IPv6 : [OFF]" | tee -a log-install.txt
echo "	Autoreboot On 05.00" | tee -a log-install.txt
echo "	Autobackup Data" | tee -a log-install.txt
echo "	Restore Data" | tee -a log-install.txt
echo "	Auto Delete Expired Account" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "==================================================================" | tee -a log-install.txt
