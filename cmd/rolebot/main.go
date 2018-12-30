package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/bwmarrin/discordgo"
	"github.com/sirupsen/logrus"

	"github.com/chronos-tachyon/rolebot/internal/bothelper"
)

var (
	flagJSON      = flag.Bool("json", false, "Write JSON to log file")
	flagLogfile   = flag.String("logfile", "", "Path to log file")
	flagTokenFile = flag.String("tokenfile", "", "Path to text file containing bot token")
	flagStateFile = flag.String("statefile", "", "Path to state file (should be writable)")
)

const (
	maxMembersPerFetch = 1000
)

var (
	reCommand   = regexp.MustCompile(`^\.(help|roles|iam(?:not)?|(?:no)?r?trust|(?:no)?auto|chan|karma(?:bump)?|debug)(?:\s+(\S.*\S))?\s*$`)
	reSpace     = regexp.MustCompile(`\s+`)
	reBrackets  = regexp.MustCompile(`\[\s*(<[#@][&!]?[0-9]+>)\s*\]`)
	reKarmaBump = regexp.MustCompile(`^\s*(<@!?[0-9]+>)\s*\+\+\s*$`)
)

type botState struct {
	Guilds map[string]*botGuildState `json:"guilds"`
}

type botGuildState struct {
	Auto                     map[string]struct{} `json:"auto"`
	BotChannelID             string              `json:"botChannelId,omitempty"`
	TrustedRoles             map[string]struct{} `json:"trustedRoles,omitempty"`
	TrustedUsers             map[string]struct{} `json:"trustedUsers,omitempty"`
	KarmaEnabled             bool                `json:"karmaEnabled,omitempty"`
	Karma                    map[string]int      `json:"karma,omitempty"`
	PersonalChannelsEnabled  bool                `json:"personalChannelsEnabled,omitempty"`
	PersonalChannelsParentID string              `json:"personalChannelsParentID"`
	PersonalChannels         map[string]string   `json:"personalChannels"`
}

var (
	gHelper  *bothelper.BotHelper
	gStateMu sync.Mutex
	gState   botState
	gLogMu   sync.Mutex
	gLog     *os.File
)

func main() {
	flag.Parse()

	sighup()

	raw, err := ioutil.ReadFile(*flagTokenFile)
	if err != nil {
		logrus.WithError(err).Fatal("ioutil.ReadFile")
	}
	token := "Bot " + string(bytes.TrimRight(raw, "\r\n"))

	raw, err = ioutil.ReadFile(*flagStateFile)
	if os.IsNotExist(err) {
		err = nil
	}
	if err != nil {
		logrus.WithError(err).Fatal("ioutil.ReadFile")
	}
	if len(raw) == 0 {
		raw = append(raw, "{}"...)
	}

	err = json.Unmarshal(raw, &gState)
	if err != nil {
		logrus.WithError(err).Fatal("json.Unmarshal")
	}

	session, err := discordgo.New(token)
	if err != nil {
		logrus.WithError(err).Fatal("discordgo.New")
	}
	session.ShouldReconnectOnError = true
	session.StateEnabled = true
	session.SyncEvents = false
	session.AddHandler(onMessage)

	gHelper = bothelper.New(session)

	err = session.Open()
	if err != nil {
		logrus.WithError(err).Fatal("session.Open")
	}
	defer session.Close()

	mainLoop()
}

func mainLoop() {
	logrus.Info("RoleBot is now running. Press Ctrl-C to exit.")

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt, os.Kill, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigch)

	for {
		sig := <-sigch
		logrus.WithField("sig", sig).Info("got signal")
		switch sig {
		case nil:
			return
		case os.Interrupt, os.Kill, syscall.SIGINT, syscall.SIGTERM:
			return
		case syscall.SIGHUP:
			sighup()
		}
	}
}

func sighup() {
	gLogMu.Lock()
	defer gLogMu.Unlock()

	var formatter logrus.Formatter
	if *flagJSON {
		formatter = &logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05Z0700",
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "@timestamp",
				logrus.FieldKeyLevel: "@level",
				logrus.FieldKeyMsg:   "@message",
			},
		}
	} else {
		formatter = &logrus.TextFormatter{
			TimestampFormat: "2006-01-02 15:04:05 Z0700",
		}
	}

	if len(*flagLogfile) == 0 {
		logrus.SetFormatter(formatter)
		logrus.SetLevel(logrus.InfoLevel)
		return
	}

	f, err := os.OpenFile(*flagLogfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		logrus.WithError(err).Fatal("os.OpenFile")
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	logrus.SetFormatter(formatter)
	logrus.SetLevel(logrus.InfoLevel)
	logrus.SetOutput(f)
	gLog, f = f, gLog
}

func onMessage(session *discordgo.Session, message *discordgo.MessageCreate) {
	self := gHelper.Me()
	u := message.Author
	if u.ID == self.ID {
		return
	}

	messageContent := message.Content
	messageContent = reSpace.ReplaceAllLiteralString(messageContent, " ")
	messageContent = reBrackets.ReplaceAllString(messageContent, "$1")
	messageContent = strings.TrimSuffix(messageContent, " ")

	var command, argument string
	if reKarmaBump.MatchString(messageContent) {
		match := reKarmaBump.FindStringSubmatch(messageContent)
		command = ".karmabump"
		argument = match[1]
	} else if strings.HasPrefix(messageContent, ".") {
		args := reSpace.Split(messageContent, 2)
		command = args[0]
		if len(args) > 1 {
			argument = strings.TrimSpace(args[1])
		}
	} else {
		return
	}

	fields := logrus.Fields{
		"command":          command,
		"argument":         argument,
		"messageContent":   message.Content,
		"messageAuthorID":  message.Author.ID,
		"messageChannelID": message.ChannelID,
	}

	c, err := session.Channel(message.ChannelID)
	if err != nil {
		logrus.WithError(err).WithFields(fields).Error("session.Channel")
		return
	}
	fields["messageChannelName"] = c.Name

	g, err := gHelper.GuildById(c.GuildID)
	if err != nil {
		logrus.WithError(err).WithFields(fields).Error("helper.Guild")
		return
	}
	fields["messageGuildID"] = g.ID

	m, err := gHelper.MemberById(g.ID, message.Author.ID)
	if err != nil {
		logrus.WithError(err).WithFields(fields).Error("helper.MemberById")
		return
	}

	nick := m.Nick
	if nick == "" {
		nick = u.Username
	}
	fields["messageAuthorName"] = u.Username + "#" + u.Discriminator
	fields["messageAuthorNick"] = nick

	gStateMu.Lock()
	defer gStateMu.Unlock()

	if gState.Guilds == nil {
		gState.Guilds = make(map[string]*botGuildState)
	}

	guild := gState.Guilds[g.ID]
	if guild == nil {
		guild = &botGuildState{}
		gState.Guilds[g.ID] = guild
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

	trustedUser := isTrusted(guild, g, u)
	fields["messageTrusted"] = trustedUser

	if guild.BotChannelID != "" && guild.BotChannelID != message.ChannelID {
		bypassDebug := (command == ".debug") && trustedUser
		bypassChan := (command == ".chan") && trustedUser
		bypass := bypassDebug || bypassChan
		if !bypass {
			return
		}
	}

	var buf bytes.Buffer
	buf.WriteString(u.Mention())
	buf.WriteString(" ")

	defer func() {
		if buf.Len() == 0 {
			return
		}
		str := buf.String()
		fields["replyText"] = str
		_, err := session.ChannelMessageSend(message.ChannelID, str)
		if err != nil {
			logrus.WithError(err).WithFields(fields).Error("session.ChannelMessageSend")
		}
	}()

	switch command {
	case ".help":
		buf.WriteString("```")
		buf.WriteString("Basic commands:\n")
		buf.WriteString(msgBasicCoreHelp)
		buf.WriteString(msgBasicRoleHelp)
		if guild.KarmaEnabled {
			buf.WriteString(msgBasicKarmaHelp)
		}
		if guild.PersonalChannelsEnabled {
			buf.WriteString(msgBasicPersonalChannelsHelp)
		}
		if argument == "advanced" {
			buf.WriteString("\n")
			buf.WriteString("Advanced commands (for trusted users):\n")
			buf.WriteString(msgAdvancedCoreHelp)
			buf.WriteString(msgAdvancedRoleHelp)
			buf.WriteString(msgAdvancedKarmaHelp)
			buf.WriteString(msgAdvancedPersonalChannelsHelp)
		}
		buf.WriteString("```")

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
		rr, valid := parseRole(&buf, fields, g, argument)
		if !valid {
			return
		}

		if !isAuto(guild, rr) {
			fmt.Fprintf(&buf, "Sorry, but I'm not allowed to grant the %q role", rr.Name)
			return
		}

		err := session.GuildMemberRoleAdd(g.ID, u.ID, rr.ID)
		if err != nil {
			logrus.WithError(err).WithFields(fields).Error("session.GuildMemberRoleAdd")
			buf.WriteString("Error while granting role!")
			return
		}

		logrus.WithFields(fields).Info("iam")
		fmt.Fprintf(&buf, "OK, you are now %q", rr.Name)

	case ".iamnot":
		rr, valid := parseRole(&buf, fields, g, argument)
		if !valid {
			return
		}

		if !isAuto(guild, rr) {
			fmt.Fprintf(&buf, "Sorry, but I'm not allowed to remove the %q role", rr.Name)
			return
		}

		err = session.GuildMemberRoleRemove(g.ID, u.ID, rr.ID)
		if err != nil {
			logrus.WithError(err).WithFields(fields).Error("session.GuildMemberRoleRemove")
			buf.WriteString("Error while revoking role!")
			return
		}

		logrus.WithFields(fields).Info("iamnot")
		fmt.Fprintf(&buf, "OK, you are not %q anymore", rr.Name)

	case ".trust":
		mm, valid := parseMember(&buf, fields, g, argument)
		if !valid {
			return
		}

		if !trustedUser {
			buf.WriteString("Sorry, but only trusted users can do that")
			return
		}

		guild.TrustedUsers[mm.User.ID] = struct{}{}
		saveState()
		logrus.WithFields(fields).Info("trust")
		fmt.Fprintf(&buf, "OK, I now trust %s", mm.User.Mention())

	case ".notrust":
		mm, valid := parseMember(&buf, fields, g, argument)
		if !valid {
			return
		}

		if !trustedUser {
			buf.WriteString("Sorry, but only trusted users can do that")
			return
		}

		delete(guild.TrustedUsers, mm.User.ID)
		saveState()
		logrus.WithFields(fields).Info("notrust")
		fmt.Fprintf(&buf, "OK, I no longer trust %s", mm.User.Mention())

	case ".rtrust":
		rr, valid := parseRole(&buf, fields, g, argument)
		if !valid {
			return
		}

		if !trustedUser {
			buf.WriteString("Sorry, but only trusted users can do that")
			return
		}

		guild.TrustedRoles[rr.ID] = struct{}{}
		saveState()
		logrus.WithFields(fields).Info("rtrust")
		fmt.Fprintf(&buf, "OK, I now trust everyone with the %q role", rr.Name)

	case ".nortrust":
		rr, valid := parseRole(&buf, fields, g, argument)
		if !valid {
			return
		}

		if !trustedUser {
			buf.WriteString("Sorry, but only trusted users can do that")
			return
		}

		delete(guild.TrustedRoles, rr.ID)
		saveState()
		logrus.WithFields(fields).Info("nortrust")
		fmt.Fprintf(&buf, "OK, I no longer trust everyone with the %q role", rr.Name)

	case ".auto":
		rr, valid := parseRole(&buf, fields, g, argument)
		if !valid {
			return
		}

		if !trustedUser {
			buf.WriteString("Sorry, but only trusted users can do that")
			return
		}

		guild.Auto[rr.ID] = struct{}{}
		saveState()
		logrus.WithFields(fields).Info("auto")
		fmt.Fprintf(&buf, "OK, I am now permitted to grant the %q role", rr.Name)

	case ".noauto":
		rr, valid := parseRole(&buf, fields, g, argument)
		if !valid {
			return
		}

		if !trustedUser {
			buf.WriteString("Sorry, but only trusted users can do that")
			return
		}

		delete(guild.Auto, rr.ID)
		saveState()
		logrus.WithFields(fields).Info("noauto")
		fmt.Fprintf(&buf, "OK, I am no longer permitted to grant the %q role", rr.Name)

	case ".chan":
		cid, msg, valid := parseChan(&buf, fields, c, g, argument)
		if !valid {
			return
		}

		if !trustedUser {
			buf.WriteString("Sorry, but only trusted users can do that")
			return
		}

		guild.BotChannelID = cid
		saveState()
		logrus.WithFields(fields).Info("chan")
		fmt.Fprintf(&buf, "OK, from now on I will accept requests %s", msg)

	case ".karma":
		if argument == "on" {
			if !trustedUser {
				buf.WriteString("Sorry, but only trusted users can do that")
				return
			}

			guild.KarmaEnabled = true
			saveState()
			logrus.WithFields(fields).Info("karma on")
			fmt.Fprintf(&buf, "OK, karma tracking is now enabled")
			return
		}

		if argument == "off" {
			if !trustedUser {
				buf.WriteString("Sorry, but only trusted users can do that")
				return
			}

			guild.KarmaEnabled = false
			saveState()
			logrus.WithFields(fields).Info("karma off")
			fmt.Fprintf(&buf, "OK, karma tracking is now disabled")
			return
		}

		if argument == "clear" || argument == "reset" {
			if !trustedUser {
				buf.WriteString("Sorry, but only trusted users can do that")
				return
			}

			guild.Karma = nil
			saveState()
			logrus.WithFields(fields).Info("karma clear")
			fmt.Fprintf(&buf, "OK, all karma scores have been reset")
			return
		}

		mm, valid := parseMember(&buf, fields, g, argument)
		if !valid {
			return
		}

		uu := mm.User
		buf.Reset()
		fmt.Fprintf(&buf, "%s has %d karma points", uu.Mention(), guild.Karma[uu.ID])

	case ".karmabump":
		if !guild.KarmaEnabled {
			buf.Reset()
			return
		}

		mm, valid := parseMember(&buf, fields, g, argument)
		if !valid {
			return
		}

		if guild.Karma == nil {
			guild.Karma = make(map[string]int)
		}
		uu := mm.User
		guild.Karma[uu.ID]++
		saveState()
		buf.Reset()
		logrus.WithFields(fields).Info("karmabump")
		fmt.Fprintf(&buf, "%s has %d karma points", uu.Mention(), guild.Karma[uu.ID])

	case ".personal":
		if argument == "on" {
			if !trustedUser {
				buf.WriteString("Sorry, but only trusted users can do that")
				return
			}

			guild.PersonalChannelsEnabled = true
			saveState()
			logrus.WithFields(fields).Info("personal on")
			fmt.Fprintf(&buf, "OK, personal channels are now enabled")
			return
		}

		if argument == "off" {
			if !trustedUser {
				buf.WriteString("Sorry, but only trusted users can do that")
				return
			}

			guild.PersonalChannelsEnabled = false
			saveState()
			logrus.WithFields(fields).Info("personal off")
			fmt.Fprintf(&buf, "OK, personal channels are now disabled")
			return
		}

		if argument == "create" {
			if !guild.PersonalChannelsEnabled {
				buf.Reset()
				return
			}

			fields["targetChannelName"] = nick
			cc, err := session.GuildChannelCreate(g.ID, nick, discordgo.ChannelTypeGuildText)
			if err != nil {
				logrus.WithError(err).WithFields(fields).Error("session.GuildChannelCreate")
				buf.WriteString("Error creating channel!")
				return
			}
			fields["targetChannelID"] = cc.ID

			if len(guild.PersonalChannelsParentID) != 0 {
				cc, err = session.ChannelEditComplex(cc.ID, &discordgo.ChannelEdit{
					ParentID: guild.PersonalChannelsParentID,
				})
				if err != nil {
					logrus.WithError(err).WithFields(fields).Error("session.ChannelEditComplex")
					session.ChannelDelete(cc.ID)
					buf.WriteString("Error creating channel!")
					return
				}
			}

			if guild.PersonalChannels == nil {
				guild.PersonalChannels = make(map[string]string)
			}
			guild.PersonalChannels[u.ID] = cc.ID
			logrus.WithFields(fields).Info("personal create")
			fmt.Fprintf(&buf, "OK, I created your channel. %s", channelMention(cc))
			return
		}

		if argument == "destroy" {
			if !guild.PersonalChannelsEnabled {
				buf.Reset()
				return
			}

			cid, found := guild.PersonalChannels[u.ID]
			if !found {
				buf.WriteString("You don't have a personal channel.")
				return
			}

			cc, err := session.Channel(cid)
			if err != nil {
				logrus.WithError(err).WithFields(fields).Error("session.Channel")
				buf.WriteString("Error finding your personal channel!")
				return
			}

			fields["targetChannelID"] = cc.ID
			fields["targetChannelName"] = cc.Name
			_, err = gHelper.ChannelDelete(cc.ID)
			if err != nil {
				logrus.WithError(err).WithFields(fields).Error("helper.ChannelDelete")
				buf.WriteString("Error deleting channel!")
				return
			}

			logrus.WithFields(fields).Info("personal destroy")
			buf.WriteString("OK, I destroyed your personal channel.")
			return
		}

		buf.WriteString("Sorry, I don't know what that means.")
		return

	case ".parent":
		if !trustedUser {
			buf.WriteString("Sorry, but only trusted users can do that")
			return
		}

		if argument == "none" {
			guild.PersonalChannelsParentID = ""
			saveState()
			logrus.WithFields(fields).Info("parent")
			buf.WriteString("OK, from now on any any personal channels I create will have no parent category.")
			return
		}

		cc, err := gHelper.CategoryByArgument(g.ID, argument)
		if err == bothelper.ErrManyFound {
			fmt.Fprintf(&buf, "Sorry, but I see multiple categories named %q", cc.Name)
			return
		}
		if err == bothelper.ErrNotFound {
			buf.WriteString("Sorry, but I don't see a category with that name")
			return
		}
		if err != nil {
			logrus.WithError(err).WithFields(fields).Error("helper.CategoryByArgument")
			buf.WriteString("Error while searching for category!")
			return
		}
		fields["targetCategoryID"] = cc.ID
		fields["targetCategoryName"] = cc.Name

		guild.PersonalChannelsParentID = cc.ID
		saveState()
		logrus.WithFields(fields).Info("parent")
		fmt.Fprintf(&buf, "OK, from now on any personal channels I create will be children of %s.", cc.Name)
		return

	case ".debug":
		if trustedUser {
			logrus.WithFields(fields).Info("debug")
		}
		return

	default:
		buf.Reset()
		return
	}
}

func channelMention(c *discordgo.Channel) string {
	return fmt.Sprintf("<#%s>", c.ID)
}

func parseChan(buf *bytes.Buffer, fields logrus.Fields, c *discordgo.Channel, g *discordgo.Guild, arg string) (cid, msg string, valid bool) {
	fields["target"] = arg

	if arg == "" || arg == "any" {
		cid = ""
		msg = "on any channel"
		valid = true
		return
	}

	if arg == "this" {
		fields["targetChannelID"] = c.ID
		fields["targetChannelName"] = c.Name
		cid = c.ID
		msg = "only on this channel"
		valid = true
		return
	}

	cc, err := gHelper.ChannelByArgument(g.ID, arg)
	if err == bothelper.ErrManyFound {
		fmt.Fprintf(buf, "Sorry, but I see multiple channels named #%s", c.Name)
		return
	}
	if err == bothelper.ErrNotFound {
		buf.WriteString("Sorry, but I don't see a channel with that name")
		return
	}
	if err != nil {
		logrus.WithError(err).WithFields(fields).Error("helper.ChannelByArgument")
		buf.WriteString("Error while searching for channel!")
		return
	}

	fields["targetChannelID"] = cc.ID
	fields["targetChannelName"] = cc.Name
	cid = cc.ID
	msg = fmt.Sprintf("only on #%s", cc.Name)
	valid = true
	return
}

func parseRole(buf *bytes.Buffer, fields logrus.Fields, g *discordgo.Guild, arg string) (r *discordgo.Role, valid bool) {
	fields["target"] = arg

	var err error
	r, err = gHelper.RoleByArgument(g.ID, arg)
	if err == bothelper.ErrManyFound {
		fmt.Fprintf(buf, "Sorry, but I see multiple roles named %q", r.Name)
		return
	}
	if err == bothelper.ErrNotFound {
		buf.WriteString("Sorry, but I don't see a role with that name")
		return
	}
	if err != nil {
		logrus.WithError(err).WithFields(fields).Error("helper.RoleByArgument")
		buf.WriteString("Error while searching for role!")
		return
	}

	fields["targetRoleID"] = r.ID
	fields["targetRoleName"] = r.Name
	valid = true
	return
}

func parseMember(buf *bytes.Buffer, fields logrus.Fields, g *discordgo.Guild, arg string) (m *discordgo.Member, valid bool) {
	fields["target"] = arg

	var err error
	m, err = gHelper.MemberByArgument(g.ID, arg)
	if err == bothelper.ErrManyFound {
		fmt.Fprintf(buf, "Sorry, but I see multiple members with the nickname %q", m.Nick)
		return
	}
	if err == bothelper.ErrNotFound {
		buf.WriteString("Sorry, but I don't see a member with that nickname")
		return
	}
	if err != nil {
		logrus.WithError(err).WithFields(fields).Error("helper.MemberByArgument")
		buf.WriteString("Error while searching for member!")
		return
	}

	u := m.User
	targetNick := m.Nick
	if targetNick == "" {
		targetNick = u.Username
	}

	fields["targetUserID"] = u.ID
	fields["targetUserName"] = u.Username + "#" + u.Discriminator
	fields["targetUserNick"] = targetNick
	valid = true
	return
}

func saveState() {
	raw, err := jsonMarshal(&gState)
	if err != nil {
		logrus.WithError(err).Fatal("json.Marshal")
	}

	err = ioutil.WriteFile(*flagStateFile, raw, 0666)
	if err != nil {
		logrus.WithError(err).Fatal("ioutil.WriteFile")
	}
}

func isAuto(guild *botGuildState, r *discordgo.Role) bool {
	_, found := guild.Auto[r.ID]
	return found
}

func isTrusted(guild *botGuildState, g *discordgo.Guild, u *discordgo.User) bool {
	if u.ID == g.OwnerID {
		return true
	}
	if _, found := guild.TrustedUsers[u.ID]; found {
		return true
	}
	if len(guild.TrustedRoles) != 0 {
		member, err := gHelper.GuildMember(g.ID, u.ID)
		if err != nil {
			logrus.WithError(err).Error("helper.GuildMember")
			return false
		}
		for _, roleID := range member.Roles {
			if _, found := guild.TrustedRoles[roleID]; found {
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

const msgBasicCoreHelp = `
.help           Show help for basic commands
.help advanced  Show help for all commands
`

const msgBasicRoleHelp = `
.roles          List available roles
.iam [role]     Add yourself to a role
.iamnot [role]  Remove yourself from a role
`

const msgBasicKarmaHelp = `
.karma [user]   Show [user]’s karma score
[user]++        Give one karma point to [user]
`

const msgBasicPersonalChannelsHelp = `
.personal create   Create your personal channel
.personal destroy  Destroy your personal channel
`

const msgAdvancedCoreHelp = `
.chan any     Listen for commands on any channel
.chan this    Listen for commands on this channel only
.chan [chan]  Listen for commands on #[chan] only

.trust [user]     Mark [user] as a trusted user
.notrust [user]   Mark [user] as a non-trusted user
.rtrust [role]    Mark [role] as a trusted role
.nortrust [role]  Mark [role] as a non-trusted role
`

const msgAdvancedRoleHelp = `
.auto [role]    Mark [role] as self-grantable
.noauto [role]  Mark [role] as non-self-grantable
`

const msgAdvancedKarmaHelp = `
.karma on     Enable karma tracking
.karma off    Disable karma tracking
.karma clear  Reset all karma scores
`

const msgAdvancedPersonalChannelsHelp = `
.personal off       Disable personal channels
.personal on        Enable personal channels
.parent [category]  Set parent category for new personal channels
`
