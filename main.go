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
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/bwmarrin/discordgo"

	"github.com/chronos-tachyon/rolebot/bothelper"
)

const (
	maxMembersPerFetch = 1000
)

var (
	flagTokenFile = flag.String("tokenfile", "", "Path to text file containing bot token")
	flagStateFile = flag.String("statefile", "", "Path to state file (should be writable)")

	reSpace    = regexp.MustCompile(`\s+`)
	reBrackets = regexp.MustCompile(`^\[(.*)\]$`)
)

type State struct {
	Guilds map[string]*GuildState `json:"guilds"`
}

type GuildState struct {
	Auto         map[string]struct{} `json:"auto"`
	BotChannelId string              `json:"botChannelId,omitempty"`
	TrustedRoles map[string]struct{} `json:"trustedRoles,omitempty"`
	TrustedUsers map[string]struct{} `json:"trustedUsers,omitempty"`
}

var (
	helper *bothelper.BotHelper
	mutex  sync.Mutex
	state  State
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

	session, err := discordgo.New(token)
	if err != nil {
		log.Fatalf("fatal: discordgo.New: %v", err)
	}
	session.ShouldReconnectOnError = true
	session.StateEnabled = true
	session.SyncEvents = false
	session.AddHandler(OnMessage)

	helper = bothelper.New(session)

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
	session.State.RLock()
	selfUserId := session.State.User.ID
	session.State.RUnlock()

	u := message.Author
	if u.ID == selfUserId {
		return
	}

	if !strings.HasPrefix(message.Content, ".") {
		return
	}

	args := reSpace.Split(message.Content, 2)
	var command, argument string
	command = args[0]
	if len(args) > 1 {
		argument = reBrackets.ReplaceAllString(args[1], "$1")
	}

	c, err := session.Channel(message.ChannelID)
	if err != nil {
		log.Printf("error: Channel: %v", err)
		return
	}

	g, err := helper.GuildById(c.GuildID)
	if err != nil {
		log.Printf("error: Guild: %v", err)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	if state.Guilds == nil {
		state.Guilds = make(map[string]*GuildState)
	}

	guild := state.Guilds[g.ID]
	if guild == nil {
		guild = &GuildState{}
		state.Guilds[g.ID] = guild
	}
	if guild.Auto == nil {
		guild.Auto = make(map[string]struct{})
	}
	if guild.TrustedRoles == nil {
		guild.TrustedRoles = make(map[string]struct{})
	}
	if guild.TrustedUsers == nil {
		guild.TrustedUsers = make(map[string]struct{})
	}

	if guild.BotChannelId != "" && guild.BotChannelId != message.ChannelID {
		bypass := (command == ".chan") && isTrusted(guild, g, u)
		if !bypass {
			return
		}
	}

	var buf bytes.Buffer
	var rr *discordgo.Role
	var mm *discordgo.Member
	var valid bool

	buf.WriteString(u.Mention())
	buf.WriteString(" ")

	switch command {
	case ".help":
		buf.WriteString(msgHelp)

	case ".roles":
		roles := make([]*discordgo.Role, len(g.Roles))
		copy(roles, g.Roles)
		sort.Sort(discordgo.Roles(roles))
		buf.WriteString("Available roles:")
		any := false
		for _, r := range roles {
			if _, found := guild.Auto[r.ID]; found {
				any = true
				fmt.Fprintf(&buf, "\n* %s", r.Name)
			}
		}
		if !any {
			buf.WriteString(" **none**")
		}

	case ".iam":
		rr, valid = parseRole(&buf, g.ID, argument)
		if valid && isAuto(guild, rr) {
			err = session.GuildMemberRoleAdd(g.ID, u.ID, rr.ID)
			if err != nil {
				log.Printf("error: GuildMemberRoleAdd: %v", err)
				buf.WriteString("Error while granting role!")
			} else {
				fmt.Fprintf(&buf, "OK, you are now %q", rr.Name)
			}
		} else if valid {
			fmt.Fprintf(&buf, "Sorry, but I'm not allowed to grant the %q role", rr.Name)
		}

	case ".iamnot":
		rr, valid = parseRole(&buf, g.ID, argument)
		if valid && isAuto(guild, rr) {
			err = session.GuildMemberRoleRemove(g.ID, u.ID, rr.ID)
			if err != nil {
				log.Printf("error: GuildMemberRoleRemove: %v", err)
				buf.WriteString("Error while revoking role!")
			} else {
				fmt.Fprintf(&buf, "OK, you are not %q anymore", rr.Name)
			}
		} else if valid {
			fmt.Fprintf(&buf, "Sorry, but I'm not allowed to remove the %q role", rr.Name)
		}

	case ".trust":
		mm, valid = parseMember(&buf, g.ID, argument)
		if valid && isTrusted(guild, g, u) {
			guild.TrustedUsers[mm.User.ID] = struct{}{}
			saveState()
			fmt.Fprintf(&buf, "OK, I now trust %s", mm.User.Mention())
		} else if valid {
			buf.WriteString("Sorry, but only trusted users can do that")
		}

	case ".notrust":
		mm, valid = parseMember(&buf, g.ID, argument)
		if valid && isTrusted(guild, g, u) {
			delete(guild.TrustedUsers, mm.User.ID)
			saveState()
			fmt.Fprintf(&buf, "OK, I no longer trust %s", mm.User.Mention())
		} else if valid {
			buf.WriteString("Sorry, but only trusted users can do that")
		}

	case ".rtrust":
		rr, valid = parseRole(&buf, g.ID, argument)
		if valid && isTrusted(guild, g, u) {
			guild.TrustedRoles[rr.ID] = struct{}{}
			saveState()
			fmt.Fprintf(&buf, "OK, I now trust everyone with the %q role", rr.Name)
		} else if valid {
			buf.WriteString("Sorry, but only trusted users can do that")
		}

	case ".nortrust":
		rr, valid = parseRole(&buf, g.ID, argument)
		if valid && isTrusted(guild, g, u) {
			delete(guild.TrustedRoles, rr.ID)
			saveState()
			fmt.Fprintf(&buf, "OK, I no longer trust everyone with the %q role", rr.Name)
		} else if valid {
			buf.WriteString("Sorry, but only trusted users can do that")
		}

	case ".auto":
		rr, valid = parseRole(&buf, g.ID, argument)
		if valid && isTrusted(guild, g, u) {
			guild.Auto[rr.ID] = struct{}{}
			saveState()
			fmt.Fprintf(&buf, "OK, I am now permitted to grant the %q role", rr.Name)
		} else if valid {
			buf.WriteString("Sorry, but only trusted users can do that")
		}

	case ".noauto":
		rr, valid = parseRole(&buf, g.ID, argument)
		if valid && isTrusted(guild, g, u) {
			delete(guild.Auto, rr.ID)
			saveState()
			fmt.Fprintf(&buf, "OK, I am no longer permitted to grant the %q role", rr.Name)
		} else if valid {
			buf.WriteString("Sorry, but only trusted users can do that")
		}

	case ".chan":
		var newbotcid, newbotmsg string
		newbotcid, newbotmsg, valid = parseChan(&buf, message.ChannelID, g.ID, argument)
		if valid && isTrusted(guild, g, u) {
			guild.BotChannelId = newbotcid
			saveState()
			fmt.Fprintf(&buf, "OK, from now on I will accept requests %s", newbotmsg)
		} else if valid {
			buf.WriteString("Sorry, but only trusted users can do that")
		}

	case ".debug":
		log.Printf("debug: %q", message.Content)
		buf.WriteString("OK, I logged that")

	default:
		return
	}

	_, err = session.ChannelMessageSend(message.ChannelID, buf.String())
	if err != nil {
		log.Printf("error: ChannelMessageSend: %v", err)
	}
}

func parseChan(buf *bytes.Buffer, tcid, gid, arg string) (cid string, msg string, valid bool) {
	if arg == "" || arg == "any" {
		cid = ""
		msg = "on any channel"
		valid = true
	} else if arg == "this" {
		cid = tcid
		msg = "only on this channel"
		valid = true
	} else {
		c, err := helper.ChannelByArgument(gid, arg)
		if err == nil {
			cid = c.ID
			msg = fmt.Sprintf("only on #%s", c.Name)
			valid = true
		} else if err == bothelper.ErrManyFound {
			fmt.Fprintf(buf, "Sorry, but I see multiple channels named #%s", c.Name)
		} else if err == bothelper.ErrNotFound {
			buf.WriteString("Sorry, but I don't see a channel with that name")
		} else {
			buf.WriteString("Error while searching for channel!")
			log.Printf("error: %v", err)
		}
	}
	return
}

func parseRole(buf *bytes.Buffer, gid, arg string) (r *discordgo.Role, valid bool) {
	var err error
	r, err = helper.RoleByArgument(gid, arg)
	if err == nil {
		valid = true
	} else if err == bothelper.ErrManyFound {
		fmt.Fprintf(buf, "Sorry, but I see multiple roles named %q", r.Name)
	} else if err == bothelper.ErrNotFound {
		buf.WriteString("Sorry, but I don't see a role with that name")
	} else {
		buf.WriteString("Error while searching for role!")
		log.Printf("error: %v", err)
	}
	return
}

func parseMember(buf *bytes.Buffer, gid, arg string) (m *discordgo.Member, valid bool) {
	var err error
	m, err = helper.MemberByArgument(gid, arg)
	if err == nil {
		valid = true
	} else if err == bothelper.ErrManyFound {
		fmt.Fprintf(buf, "Sorry, but I see multiple members with the nickname %q", m.Nick)
	} else if err == bothelper.ErrNotFound {
		buf.WriteString("Sorry, but I don't see a member with that nickname")
	} else {
		buf.WriteString("Error while searching for member!")
		log.Printf("error: %v", err)
	}
	return
}

func saveState() {
	raw, err := jsonMarshal(&state)
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

func isAuto(guild *GuildState, r *discordgo.Role) bool {
	_, found := guild.Auto[r.ID]
	return found
}

func isTrusted(guild *GuildState, g *discordgo.Guild, u *discordgo.User) bool {
	if u.ID == g.OwnerID {
		return true
	}
	if _, found := guild.TrustedUsers[u.ID]; found {
		return true
	}
	if len(guild.TrustedRoles) != 0 {
		member, err := helper.GuildMember(g.ID, u.ID)
		if err != nil {
			log.Printf("error: GuildMember: %v", err)
			return false
		}
		for _, roleId := range member.Roles {
			if _, found := guild.TrustedRoles[roleId]; found {
				return true
			}
		}
	}
	return false
}

func jsonMarshal(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetIndent("", "  ")
	err := e.Encode(v)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const msgHelp = "```" + `Standard commands:

.help           Show this message
.roles          List available roles

.iam [role]     Add yourself to a role
.iamnot [role]  Remove yourself from a role

Trusted commands:

.chan any         Listen for commands on any channel
.chan this        Listen for commands on this channel only
.chan [chan]      Listen for commands on #[chan] only

.trust [user]     Mark user as a trusted user
.notrust [user]   Mark user as a non-trusted user
.rtrust [role]    Mark role as a trusted role
.nortrust [role]  Mark role as a non-trusted role

.auto [role]      Mark role as self-grantable
.noauto [role]    Mark role as non-self-grantable
` + "```"
