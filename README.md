# RoleBot
A bot for user-assigned chat roles in Discord.

## Using RoleBot

First, make sure you're in the right channel. There is probably a channel
called `#botspam`.  Any bot commands you type should be entered there.

To give yourself the role "foo", type `.iam foo`.

If you decide you don't want the role "foo" anymore, type `.iamnot foo`.

## Adding RoleBot to your server

If you want RoleBot and you trust me to keep it running, then all you need to
do is this:

* Visit https://discordapp.com/oauth2/authorize?client_id=362058035167887361&scope=bot

* Select your server and click Authorize to invite the bot

* Create a role for RoleBot, enable the "Manage Roles" permission, and place
  the role higher in the list than any role that RoleBot should hand out

* Give RoleBot the role that you created

## Setting up RoleBot for your server

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

## Running your own RoleBot under Linux

* Install Go and set it up for your local environment

* Note that the following instructions assume a `GOPATH` of `~/go`

* Fetch the source code with `go get github.com/chronos-tachyon/rolebot`

* Run `mkdir ~/.rolebot`

* Run `cp ~/go/src/github.com/chronos-tachyon/rolebot/*.sh ~/.rolebot`

* Visit https://discordapp.com/developers/applications/me

* Create an app — it needs a name and an icon

* Once the app is created, give it a Bot User

* Click to reveal the Bot User token

* Run `touch ~/.rolebot/token && chmod 0600 ~/.rolebot/token`

* Run `cat > ~/.rolebot/token`, paste the token, hit ENTER then CTRL-D

* Run `~/.rolebot/start.sh` to start the bot, `~/.rolebot/stop.sh` to stop it,
  or `~/.rolebot/restart.sh` to restart it

* Go back to the bot application page and copy the client ID

* Add the bot to your server by visiting
  `https://discordapp.com/oauth2/authorize?client_id=<id>&scope=bot`,
  where `<id>` is the value from the bot application page

