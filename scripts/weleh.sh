#!/bin/bash

wget -q -O /usr/local/bin/ws-dropbear https://raw.githubusercontent.com/cybertize/joekers/default/files/dropbear-ws.py
wget -q -O /usr/local/bin/ws-stunnel https://raw.githubusercontent.com/cybertize/joekers/default/files/ws-stunnel.py
chmod +x /usr/local/bin/ws-dropbear
chmod +x /usr/local/bin/ws-stunnel

wget -q -O /etc/systemd/system/ws-dropbear.service https://raw.githubusercontent.com/cybertize/joekers/default/files/ws-dropbear.service && chmod +x /etc/systemd/system/ws-dropbear.service

wget -q -O /etc/systemd/system/ws-stunnel.service https://raw.githubusercontent.com/cybertize/joekers/default/files/ws-stunnel.service && chmod +x /etc/systemd/system/ws-stunnel.service

systemctl daemon-reload

systemctl enable ws-dropbear.service
systemctl start ws-dropbear.service
systemctl restart ws-dropbear.service

systemctl enable ws-stunnel.service
systemctl start ws-stunnel.service
systemctl restart ws-stunnel.service
