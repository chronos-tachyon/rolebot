#!/bin/bash
set -eu -o pipefail

tmpdir="$(mktemp -t -d install-rolebot.$$.XXXXXXXX)"
trap 'rm -rf "$tmpdir"' EXIT

if ! getent passwd rolebot &>/dev/null ; then
  adduser \
    --system \
    --group \
    --shell /bin/bash \
    --gecos RoleBot \
    --disabled-password \
    rolebot
fi

rolebot_home=~rolebot
sed -e "s|/home/rolebot/|${rolebot_home}/|g" < rolebot.exec.sh   > "${tmpdir}/exec.sh"
sed -e "s|/home/rolebot/|${rolebot_home}/|g" < rolebot.logrotate > "${tmpdir}/logrotate"
sed -e "s|/home/rolebot/|${rolebot_home}/|g" < rolebot.service   > "${tmpdir}/service"

install -o root     -g root     -m 0755 rolebot               /usr/local/bin/rolebot
install -o root     -g root     -m 0644 "${tmpdir}/service"   /etc/systemd/system/rolebot.service
install -o root     -g root     -m 0644 "${tmpdir}/logrotate" /etc/logrotate.d/rolebot
install -o rolebot  -g rolebot  -m 0700 -d                    "${rolebot_home}/bin"
install -o rolebot  -g rolebot  -m 0700 "${tmpdir}/exec.sh"   "${rolebot_home}/bin/exec.sh"

if [ ! -f "${rolebot_home}/token" ]; then
  echo "You need an OAuth2 token!"
  echo "Step 1: Visit https://discordapp.com/developers/applications/me"
  echo "Step 2: Register a bot account"
  echo "Step 3: Turn it into a Bot User"
  echo "Step 4: Under Bot, find Token and click 'click to reveal'"
  read -p "Token: " token
  ( umask 077; echo "$token" > "${tmpdir}/token" )
  install -o rolebot -g rolebot -m 0400 "${tmpdir}/token" "${rolebot_home}/token"
fi

if [ ! -f "${rolebot_home}/state" ]; then
  ( umask 077; echo "{}" > "${tmpdir}/state" )
  install -o rolebot -g rolebot -m 0600 "${tmpdir}/state" "${rolebot_home}/state"
fi

systemctl daemon-reload
systemctl enable rolebot.service
systemctl start rolebot.service
