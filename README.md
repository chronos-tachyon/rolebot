# RoleBot
A bot for user-assigned chat roles in Discord.

## For users
### Using RoleBot

First, make sure you're in the right channel. There is probably a channel
called `#botspam`.  Any bot commands you type should be entered there.

To give yourself the role "foo", type `.iam foo`.

If you decide you don't want the role "foo" anymore, type `.iamnot foo`.

## For server owners
### Adding RoleBot to your server

If you want RoleBot and you trust me to keep it running, then all you need to
do is this:

* Visit https://discordapp.com/oauth2/authorize?client_id=362058035167887361&scope=bot

* Select your server and click Authorize to invite the bot

* Create a role for RoleBot, enable the "Manage Roles" permission, and place
  the role higher in the list than any role that RoleBot should hand out

* Give RoleBot the role that you created

### Setting up RoleBot for your server

When the bot is first added to the server, it will only accept admin commands
from the server owner. The server owner can indicate that other users and
roles are "trusted", meaning that they can also issue admin commands.

To only accept commands on a channel named "botspam", type `.chan botspam`.

To trust a user named "alice", type `.trust alice`.

If you change your mind about trusting user "alice", type `.notrust alice`.

To trust any user in the role "mods", type `.rtrust mods`.

If you change your mind about trusting anyone with the "mods" role, type
`.nortrust mods`.

To allow regular users to give themselves role "foo", type `.auto foo`.

To lock down the "foo" role, type `.noauto foo`.

## For developers and advanced server owners
### Running your own RoleBot under Linux

First, if you don't already have it, install Go:

```sh
mkdir -p ~/tmp
cd ~/tmp
curl -O https://dl.google.com/go/go1.10.linux-amd64.tar.gz
tar xzf go1.10.linux-amd64.tar.gz
mv go ~/goroot
echo 'export GOPATH="${HOME}/go"' >>~/.bashrc
echo 'export GOROOT="${HOME}/goroot"' >>~/.bashrc
echo 'export PATH="${GOPATH}/bin:${GOROOT}/bin:${PATH}"' >>~/.bashrc
. ~/.bashrc
```

Next, install the vgo tool:

```sh
go get -u golang.org/x/vgo
```

Now it's time to download, build, and install Rolebot:

```sh
git clone https://github.com/chronos-tachyon/rolebot.git ~/rolebot
cd ~/rolebot
./build.sh
sudo ./rolebot.install.sh
```

The install script will prompt you to obtain a Bot User token.  You will
need to visit [https://discordapp.com/developers/applications/me][apps]
and create a Discord App for your bot, at which point you'll be able to
obtain the secret token for the bot account.

Finally, add your bot to some servers!  First, go back to
[the apps page][apps], click through to your app, and copy the Client ID.
(It's at the top of the page.)  Second, add the bot to your server by
visiting `https://discordapp.com/oauth2/authorize?client_id=<id>&scope=bot`
and granting access to the server.

Lastly, you will need to grant the bot some limited moderator powers.  Bot
permissions on the server work just like people permissions.

[apps]: https://discordapp.com/developers/applications/me
