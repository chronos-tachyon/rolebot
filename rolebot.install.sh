#!/bin/bash
set -eu -o pipefail

tmpdir="$(mktemp -t -d install-rolebot.$$.XXXXXXXX)"
trap 'rm -rf "$tmpdir"' EXIT

if ! getent passwd rolebot &>/dev/null ; then
  useradd \
    --system \
    --user-group \
    --home-dir /var/lib/rolebot \
    --comment rolebot \
    rolebot
fi

install -o rolebot -g rolebot -m 0750 -d /var/lib/rolebot
install -o rolebot -g adm -m 0750 -d /var/log/rolebot
install -o root -g root -m 0755 rolebot /usr/local/bin/rolebot
install -o root -g root -m 0644 rolebot.service /etc/systemd/system/rolebot.service
install -o root -g root -m 0644 rolebot.logrotate /etc/logrotate.d/rolebot

if [ ! -f /var/lib/rolebot/token ]; then
  echo "You need an OAuth2 token!"
  echo "Step 1: Visit https://discordapp.com/developers/applications/me"
  echo "Step 2: Register a bot account"
  echo "Step 3: Turn it into a Bot User"
  echo "Step 4: Under Bot, find Token and click 'click to reveal'"
  read -p "Token: " token
  ( umask 077; echo "$token" > "${tmpdir}/token" )
  install -o rolebot -g rolebot -m 0400 "${tmpdir}/token" /var/lib/rolebot/token
fi

if [ ! -f /var/lib/rolebot/state ]; then
  ( umask 077; echo "{}" > "${tmpdir}/state" )
  install -o rolebot -g rolebot -m 0600 "${tmpdir}/state" /var/lib/rolebot/state
fi

systemctl enable rolebot.service
systemctl start rolebot.service
