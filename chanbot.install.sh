#!/bin/bash
set -eu -o pipefail

tmpdir="$(mktemp -t -d install-chanbot.$$.XXXXXXXX)"
trap 'rm -rf "$tmpdir"' EXIT

if ! getent passwd chanbot &>/dev/null ; then
  useradd \
    --system \
    --user-group \
    --home-dir /var/lib/chanbot \
    --comment chanbot \
    chanbot
fi

install -o chanbot -g chanbot -m 0750 -d /var/lib/chanbot
install -o chanbot -g adm -m 0750 -d /var/log/chanbot
install -o root -g root -m 0755 chanbot /usr/local/bin/chanbot
install -o root -g root -m 0644 chanbot.service /etc/systemd/system/chanbot.service
install -o root -g root -m 0644 chanbot.logrotate /etc/logrotate.d/chanbot

if [ ! -f /var/lib/chanbot/token ]; then
  echo "You need an OAuth2 token!"
  echo "Step 1: Visit https://discordapp.com/developers/applications/me"
  echo "Step 2: Register a bot account"
  echo "Step 3: Turn it into a Bot User"
  echo "Step 4: Under Bot, find Token and click 'click to reveal'"
  read -p "Token: " token
  ( umask 077; echo "$token" > "${tmpdir}/token" )
  install -o chanbot -g chanbot -m 0400 "${tmpdir}/token" /var/lib/chanbot/token
fi

systemctl enable chanbot.service
systemctl start chanbot.service
