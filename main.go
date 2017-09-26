package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/bwmarrin/discordgo"
)

var (
	flagTokenFile = flag.String("tokenfile", "", "Path to text file containing bot token")
	flagStateFile = flag.String("statefile", "", "Path to state file (should be writable)")
)

var (
	reSpace = regexp.MustCompile(`\s+`)
)

type State struct {
	sync.Mutex
	Guilds map[string]*GuildState `json:"guilds"`
}

type GuildState struct {
	Auto         map[string]struct{} `json:"auto"`
	BotChannelId string              `json:"botChannelId,omitempty"`
}

var (
	session *discordgo.Session
	state   State
)

func main() {
	flag.Parse()

	raw, err := ioutil.ReadFile(*flagTokenFile)
	if err != nil {
		log.Fatalf("fatal: ReadFile: %s: %v", *flagTokenFile, err)
	}

	token := "Bot " + string(bytes.TrimRight(raw, "\r\n"))

	raw, err = ioutil.ReadFile(*flagStateFile)
	if err != nil {
		if isNotFound(err) {
			raw = []byte("{}")
		} else {
			log.Fatalf("fatal: ReadFile: %s: %v", *flagStateFile, err)
		}
	}

	err = json.Unmarshal(raw, &state)
	if err != nil {
		log.Fatalf("fatal: json.Unmarshal: %v", err)
	}

	session, err = discordgo.New(token)
	if err != nil {
		log.Fatalf("fatal: discordgo.New: %v", err)
	}
	session.ShouldReconnectOnError = true
	session.StateEnabled = true
	session.SyncEvents = false
	session.AddHandler(OnMessage)

	err = session.Open()
	if err != nil {
		log.Fatalf("fatal: Session.Open: %v", err)
	}
	defer session.Close()

	log.Println("RoleBot is now running. Press Ctrl-C to exit.")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, os.Interrupt, os.Kill)
	<-sig
}

func OnMessage(session *discordgo.Session, message *discordgo.MessageCreate) {
	if message.Author.ID == session.State.User.ID {
		return
	}

	if !strings.HasPrefix(message.Content, ".") {
		return
	}

	args := reSpace.Split(message.Content, 2)
	var command, argument, k string
	command = args[0]
	if len(args) > 1 {
		argument = args[1]
		k = key(argument)
	}

	cid := message.ChannelID
	c, err := session.Channel(cid)
	if err != nil {
		log.Printf("error: Channel: %v", err)
		return
	}

	gid := c.GuildID
	g, err := session.Guild(gid)
	if err != nil {
		log.Printf("error: Guild: %v", err)
		return
	}

	state.Lock()
	defer state.Unlock()

	guild := state.Guilds[gid]
	if guild == nil {
		guild = &GuildState{
			Auto: make(map[string]struct{}),
		}
		if state.Guilds == nil {
			state.Guilds = make(map[string]*GuildState)
		}
		state.Guilds[gid] = guild
	}
	auto := guild.Auto
	botcid := guild.BotChannelId

	if botcid != "" && botcid != message.ChannelID {
		bypass := (message.Author.ID == g.OwnerID && command == ".chan")
		if !bypass {
			return
		}
	}

	chansByName := make(map[string]*discordgo.Channel, len(g.Channels))
	chansCollide := make(map[string]struct{}, 0)
	for _, x := range g.Channels {
		k := key(x.Name)
		if _, exists := chansByName[k]; exists {
			chansCollide[k] = struct{}{}
		} else {
			chansByName[k] = x
		}
	}

	rolesById := make(map[string]*discordgo.Role, len(g.Roles))
	rolesByName := make(map[string]*discordgo.Role, len(g.Roles))
	rolesCollide := make(map[string]struct{}, 0)
	for _, x := range g.Roles {
		k := key(x.Name)
		rolesById[x.ID] = x
		if _, exists := rolesByName[k]; exists {
			rolesCollide[k] = struct{}{}
		} else {
			rolesByName[k] = x
		}
	}

	var buf bytes.Buffer
	var r *discordgo.Role
	var ch *discordgo.Channel

	switch command {
	case ".help":
		buf.WriteString(msgHelp)

	case ".roles":
		buf.WriteString("Available roles:")
		for rid := range auto {
			r = rolesById[rid]
			if r == nil {
				continue
			}
			fmt.Fprintf(&buf, "\n  %s", r.Name)
		}
		buf.WriteString("\n.")

	case ".iam":
		r = rolesByName[k]
		if r == nil {
			buf.WriteString("There are no roles with that name")
		} else if _, found := rolesCollide[k]; found {
			fmt.Fprintf(&buf, "Multiple roles have the name %q", r.Name)
		} else if _, found := auto[r.ID]; !found {
			fmt.Fprintf(&buf, "I cannot grant the role %q", r.Name)
		} else {
			err = session.GuildMemberRoleAdd(gid, message.Author.ID, r.ID)
			if err != nil {
				log.Printf("error: GuildMemberRoleAdd: %v", err)
				buf.WriteString("Error while granting role!")
			} else {
				fmt.Fprintf(&buf, "Granted role %q to user", r.Name)
			}
		}

	case ".iamnot":
		r = rolesByName[k]
		if r == nil {
			buf.WriteString("There are no roles with that name")
		} else if _, found := rolesCollide[k]; found {
			fmt.Fprintf(&buf, "Multiple roles have the name %q", r.Name)
		} else if _, found := auto[r.ID]; !found {
			fmt.Fprintf(&buf, "I cannot revoke the role %q", r.Name)
		} else {
			err = session.GuildMemberRoleRemove(gid, message.Author.ID, r.ID)
			if err != nil {
				log.Printf("error: GuildMemberRoleRemove: %v", err)
				buf.WriteString("Error while revoking role!")
			} else {
				fmt.Fprintf(&buf, "Revoked role %q to user", r.Name)
			}
		}

	case ".auto":
		r = rolesByName[k]
		if message.Author.ID != g.OwnerID {
			buf.WriteString("Only the owner can do that")
		} else if r == nil {
			buf.WriteString("There are no roles with that name")
		} else if _, found := rolesCollide[k]; found {
			fmt.Fprintf(&buf, "Multiple roles have the name %q", r.Name)
		} else {
			auto[r.ID] = struct{}{}
			saveState()
			fmt.Fprintf(&buf, "The role %q is now self-grantable", r.Name)
		}

	case ".noauto":
		r = rolesByName[k]
		if message.Author.ID != g.OwnerID {
			buf.WriteString("Only the owner can do that")
		} else if r == nil {
			buf.WriteString("There are no roles with that name")
		} else if _, found := rolesCollide[k]; found {
			fmt.Fprintf(&buf, "Multiple roles have the name %q", r.Name)
		} else {
			delete(auto, r.ID)
			saveState()
			fmt.Fprintf(&buf, "The role %q is no longer self-grantable", r.Name)
		}

	case ".chan":
		ch = chansByName[k]
		if message.Author.ID != g.OwnerID {
			buf.WriteString("Only the owner can do that")
		} else if argument == "any" {
			guild.BotChannelId = ""
			saveState()
			buf.WriteString("OK, will accept requests on any channel")
		} else if argument == "this" {
			guild.BotChannelId = message.ChannelID
			saveState()
			buf.WriteString("OK, will only accept requests on this channel")
		} else if ch == nil {
			buf.WriteString("No channel with that name")
		} else if _, found := chansCollide[k]; found {
			buf.WriteString("Multiple channels with that name")
		} else {
			guild.BotChannelId = ch.ID
			saveState()
			fmt.Fprintf(&buf, "OK, will only accept requests on channel %s", ch.Name)
		}
	}

	_, err = session.ChannelMessageSend(cid, buf.String())
	if err != nil {
		log.Printf("error: ChannelMessageSend: %v", err)
	}
}

func saveState() {
	raw, err := json.Marshal(&state)
	if err != nil {
		log.Fatalf("fatal: json.Marshal: %v", err)
	}

	err = ioutil.WriteFile(*flagStateFile, raw, 0666)
	if err != nil {
		log.Fatalf("fatal: ioutil.WriteFile: %s: %v", *flagStateFile, err)
	}
}

func isNotFound(err error) bool {
	if pathErr, ok := err.(*os.PathError); ok {
		if errnoErr, ok := pathErr.Err.(syscall.Errno); ok {
			return errnoErr == syscall.ENOENT
		}
	}
	return false
}

func key(s string) string {
	b := []byte(s)
	b = bytes.ToLower(b)
	b = bytes.TrimLeft(b, "#@")
	b = bytes.TrimSpace(b)
	b = append(b, '/', 'K')
	return string(b)
}

const msgHelp = "```" + `
.help         Show this message
.roles        List available roles
.iam role     Add yourself to a role
.iamnot role  Remove yourself from a role
.auto role    Mark role as user-managed (owner only)
.noauto role  Mark role as admin-managed (owner only)
.chan #chan   Bot will ignore commands except on #chan (owner only)
.chan any     Bot will not ignore commands (owner only)
` + "```"
