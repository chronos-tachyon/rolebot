package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	stdlog "log"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/hashicorp/go-multierror"
	getopt "github.com/pborman/getopt/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/journald"
	"github.com/rs/zerolog/log"

	"github.com/chronos-tachyon/rolebot/internal/bothelper"
)

var appVersion = "devel"

var (
	flagVersion     bool
	flagDebug       bool
	flagTrace       bool
	flagLogStderr   bool
	flagLogJournald bool
	flagLogFile     string
	flagTokenFile   string
	flagStateFile   string
)

func init() {
	getopt.FlagLong(&flagVersion, "version", 'V', "print version and exit")
	getopt.FlagLong(&flagDebug, "verbose", 'v', "enable debug logging")
	getopt.FlagLong(&flagTrace, "debug", 'd', "enable debug and trace logging")
	getopt.FlagLong(&flagLogStderr, "log-stderr", 'S', "log JSON to stderr")
	getopt.FlagLong(&flagLogJournald, "log-journald", 'J', "log to journald")
	getopt.FlagLong(&flagLogFile, "log-file", 'l', "log JSON to file")
	getopt.FlagLong(&flagTokenFile, "tokenfile", 0, "Path to text file containing bot token")
	getopt.FlagLong(&flagStateFile, "statefile", 0, "Path to state file (should be writable)")
}

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
	gLogger  *logWriter
	gHelper  *bothelper.BotHelper
	gStateMu sync.Mutex
	gState   botState
)

func main() {
	getopt.Parse()

	if flagVersion {
		fmt.Println(appVersion)
		os.Exit(0)
	}

	if flagLogStderr && flagLogJournald {
		fmt.Fprintln(os.Stderr, "fatal: flags '--log-stderr' and '--log-journald' are mutually exclusive")
		os.Exit(1)
	}
	if flagLogStderr && flagLogFile != "" {
		fmt.Fprintln(os.Stderr, "fatal: flags '--log-stderr' and '--log-file' are mutually exclusive")
		os.Exit(1)
	}
	if flagLogJournald && flagLogFile != "" {
		fmt.Fprintln(os.Stderr, "fatal: flags '--log-journald' and '--log-file' are mutually exclusive")
		os.Exit(1)
	}

	if flagLogFile != "" {
		abs, err := filepath.Abs(flagLogFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
			os.Exit(1)
		}
		flagLogFile = abs
	}

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.DurationFieldUnit = time.Second
	zerolog.DurationFieldInteger = false
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if flagDebug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	if flagTrace {
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	}

	switch {
	case flagLogStderr:
		// do nothing

	case flagLogJournald:
		log.Logger = log.Output(journald.NewJournalDWriter())

	case flagLogFile != "":
		var err error
		gLogger, err = newLogWriter(flagLogFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fatal: failed to open log file for append: %q: %v\n", flagLogFile, err)
			os.Exit(1)
		}
		defer gLogger.Close()
		log.Logger = log.Output(gLogger)

	default:
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	stdlog.SetFlags(0)
	stdlog.SetOutput(log.Logger)

	logger := &log.Logger

	sighup(logger)

	raw, err := ioutil.ReadFile(flagTokenFile)
	if err != nil {
		logger.Fatal().
			Str("tokenFile", flagTokenFile).
			Err(err).
			Msg("ioutil.ReadFile")
	}
	token := "Bot " + string(bytes.TrimRight(raw, "\r\n"))

	raw, err = ioutil.ReadFile(flagStateFile)
	if os.IsNotExist(err) {
		err = nil
	}
	if err != nil {
		logger.Fatal().
			Str("stateFile", flagStateFile).
			Err(err).
			Msg("ioutil.ReadFile")
	}
	if len(raw) == 0 {
		raw = append(raw, "{}"...)
	}

	err = json.Unmarshal(raw, &gState)
	if err != nil {
		logger.Fatal().
			Str("stateFile", flagStateFile).
			Err(err).
			Msg("json.Unmarshal")
	}

	session, err := discordgo.New(token)
	if err != nil {
		logger.Fatal().
			Err(err).
			Msg("discordgo.New")
	}
	session.ShouldReconnectOnError = true
	session.StateEnabled = true
	session.SyncEvents = false
	session.AddHandler(func(session *discordgo.Session, message *discordgo.MessageCreate) {
		onMessage(logger, session, message)
	})

	gHelper = bothelper.New(session)

	err = session.Open()
	if err != nil {
		logger.Fatal().
			Err(err).
			Msg("session.Open")
	}
	defer session.Close()

	mainLoop(logger)
}

func mainLoop(logger *zerolog.Logger) {
	logger.Info().
		Msg("RoleBot is now running. Press Ctrl-C to exit.")

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt, os.Kill, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigch)

	for {
		sig := <-sigch
		logger.Info().
			Stringer("sig", sig).
			Msg("got signal")
		switch sig {
		case nil:
			return
		case os.Interrupt, os.Kill, syscall.SIGINT, syscall.SIGTERM:
			return
		case syscall.SIGHUP:
			sighup(logger)
		}
	}
}

func sighup(logger *zerolog.Logger) {
	if gLogger != nil {
		err := gLogger.Rotate()
		if err != nil {
			logger.Fatal().
				Err(err).
				Msg("LogWriter.Rotate")
		}
	}
}

func onMessage(logger *zerolog.Logger, session *discordgo.Session, message *discordgo.MessageCreate) {
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

	tmpLogger := logger.With().
		Str("command", command).
		Str("argument", argument).
		Str("messageContent", message.Content).
		Str("messageAuthorID", message.Author.ID).
		Str("messageChannelID", message.ChannelID).
		Logger()
	logger = &tmpLogger

	c, err := session.Channel(message.ChannelID)
	if err != nil {
		logger.Error().
			Err(err).
			Msg("session.Channel")
		return
	}

	logger.UpdateContext(func(logctx zerolog.Context) zerolog.Context {
		return logctx.Str("messageChannelName", c.Name)
	})

	g, err := gHelper.GuildById(c.GuildID)
	if err != nil {
		logger.Error().
			Err(err).
			Msg("helper.Guild")
		return
	}

	logger.UpdateContext(func(logctx zerolog.Context) zerolog.Context {
		return logctx.Str("messageGuildID", g.ID)
	})

	m, err := gHelper.MemberById(g.ID, message.Author.ID)
	if err != nil {
		logger.Error().
			Err(err).
			Msg("helper.MemberById")
		return
	}

	nick := m.Nick
	if nick == "" {
		nick = u.Username
	}

	logger.UpdateContext(func(logctx zerolog.Context) zerolog.Context {
		return logctx.
			Str("messageAuthorName", u.Username+"#"+u.Discriminator).
			Str("messageAuthorNick", nick)
	})

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

	trustedUser := isTrusted(logger, guild, g, u)
	logger.UpdateContext(func(logctx zerolog.Context) zerolog.Context {
		return logctx.Bool("messageTrusted", trustedUser)
	})

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
		logger.UpdateContext(func(logctx zerolog.Context) zerolog.Context {
			return logctx.Str("replyText", str)
		})
		_, err := session.ChannelMessageSend(message.ChannelID, str)
		if err != nil {
			logger.Error().
				Err(err).
				Msg("session.ChannelMessageSend")
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
		rr, valid := parseRole(&buf, logger, g, argument)
		if !valid {
			return
		}

		if !isAuto(guild, rr) {
			fmt.Fprintf(&buf, "Sorry, but I'm not allowed to grant the %q role", rr.Name)
			return
		}

		err := session.GuildMemberRoleAdd(g.ID, u.ID, rr.ID)
		if err != nil {
			logger.Error().
				Err(err).
				Msg("session.GuildMemberRoleAdd")
			buf.WriteString("Error while granting role!")
			return
		}

		logger.Info().
			Msg("iam")
		fmt.Fprintf(&buf, "OK, you are now %q", rr.Name)

	case ".iamnot":
		rr, valid := parseRole(&buf, logger, g, argument)
		if !valid {
			return
		}

		if !isAuto(guild, rr) {
			fmt.Fprintf(&buf, "Sorry, but I'm not allowed to remove the %q role", rr.Name)
			return
		}

		err = session.GuildMemberRoleRemove(g.ID, u.ID, rr.ID)
		if err != nil {
			logger.Error().
				Err(err).
				Msg("session.GuildMemberRoleRemove")
			buf.WriteString("Error while revoking role!")
			return
		}

		logger.Info().
			Msg("iamnot")
		fmt.Fprintf(&buf, "OK, you are not %q anymore", rr.Name)

	case ".trust":
		mm, valid := parseMember(&buf, logger, g, argument)
		if !valid {
			return
		}

		if !trustedUser {
			buf.WriteString("Sorry, but only trusted users can do that")
			return
		}

		guild.TrustedUsers[mm.User.ID] = struct{}{}
		saveState(logger)
		logger.Info().
			Msg("trust")
		fmt.Fprintf(&buf, "OK, I now trust %s", mm.User.Mention())

	case ".notrust":
		mm, valid := parseMember(&buf, logger, g, argument)
		if !valid {
			return
		}

		if !trustedUser {
			buf.WriteString("Sorry, but only trusted users can do that")
			return
		}

		delete(guild.TrustedUsers, mm.User.ID)
		saveState(logger)
		logger.Info().
			Msg("notrust")
		fmt.Fprintf(&buf, "OK, I no longer trust %s", mm.User.Mention())

	case ".rtrust":
		rr, valid := parseRole(&buf, logger, g, argument)
		if !valid {
			return
		}

		if !trustedUser {
			buf.WriteString("Sorry, but only trusted users can do that")
			return
		}

		guild.TrustedRoles[rr.ID] = struct{}{}
		saveState(logger)
		logger.Info().
			Msg("rtrust")
		fmt.Fprintf(&buf, "OK, I now trust everyone with the %q role", rr.Name)

	case ".nortrust":
		rr, valid := parseRole(&buf, logger, g, argument)
		if !valid {
			return
		}

		if !trustedUser {
			buf.WriteString("Sorry, but only trusted users can do that")
			return
		}

		delete(guild.TrustedRoles, rr.ID)
		saveState(logger)
		logger.Info().
			Msg("nortrust")
		fmt.Fprintf(&buf, "OK, I no longer trust everyone with the %q role", rr.Name)

	case ".auto":
		rr, valid := parseRole(&buf, logger, g, argument)
		if !valid {
			return
		}

		if !trustedUser {
			buf.WriteString("Sorry, but only trusted users can do that")
			return
		}

		guild.Auto[rr.ID] = struct{}{}
		saveState(logger)
		logger.Info().
			Msg("auto")
		fmt.Fprintf(&buf, "OK, I am now permitted to grant the %q role", rr.Name)

	case ".noauto":
		rr, valid := parseRole(&buf, logger, g, argument)
		if !valid {
			return
		}

		if !trustedUser {
			buf.WriteString("Sorry, but only trusted users can do that")
			return
		}

		delete(guild.Auto, rr.ID)
		saveState(logger)
		logger.Info().
			Msg("noauto")
		fmt.Fprintf(&buf, "OK, I am no longer permitted to grant the %q role", rr.Name)

	case ".chan":
		cid, msg, valid := parseChan(&buf, logger, c, g, argument)
		if !valid {
			return
		}

		if !trustedUser {
			buf.WriteString("Sorry, but only trusted users can do that")
			return
		}

		guild.BotChannelID = cid
		saveState(logger)
		logger.Info().
			Msg("chan")
		fmt.Fprintf(&buf, "OK, from now on I will accept requests %s", msg)

	case ".karma":
		if argument == "on" {
			if !trustedUser {
				buf.WriteString("Sorry, but only trusted users can do that")
				return
			}

			guild.KarmaEnabled = true
			saveState(logger)
			logger.Info().
				Msg("karma on")
			fmt.Fprintf(&buf, "OK, karma tracking is now enabled")
			return
		}

		if argument == "off" {
			if !trustedUser {
				buf.WriteString("Sorry, but only trusted users can do that")
				return
			}

			guild.KarmaEnabled = false
			saveState(logger)
			logger.Info().
				Msg("karma off")
			fmt.Fprintf(&buf, "OK, karma tracking is now disabled")
			return
		}

		if argument == "clear" || argument == "reset" {
			if !trustedUser {
				buf.WriteString("Sorry, but only trusted users can do that")
				return
			}

			guild.Karma = nil
			saveState(logger)
			logger.Info().
				Msg("karma clear")
			fmt.Fprintf(&buf, "OK, all karma scores have been reset")
			return
		}

		mm, valid := parseMember(&buf, logger, g, argument)
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

		mm, valid := parseMember(&buf, logger, g, argument)
		if !valid {
			return
		}

		if guild.Karma == nil {
			guild.Karma = make(map[string]int)
		}
		uu := mm.User
		guild.Karma[uu.ID]++
		saveState(logger)
		buf.Reset()
		logger.Info().
			Msg("karmabump")
		fmt.Fprintf(&buf, "%s has %d karma points", uu.Mention(), guild.Karma[uu.ID])

	case ".personal":
		if argument == "on" {
			if !trustedUser {
				buf.WriteString("Sorry, but only trusted users can do that")
				return
			}

			guild.PersonalChannelsEnabled = true
			saveState(logger)
			logger.Info().
				Msg("personal on")
			fmt.Fprintf(&buf, "OK, personal channels are now enabled")
			return
		}

		if argument == "off" {
			if !trustedUser {
				buf.WriteString("Sorry, but only trusted users can do that")
				return
			}

			guild.PersonalChannelsEnabled = false
			saveState(logger)
			logger.Info().
				Msg("personal off")
			fmt.Fprintf(&buf, "OK, personal channels are now disabled")
			return
		}

		if argument == "create" {
			if !guild.PersonalChannelsEnabled {
				buf.Reset()
				return
			}

			logger.UpdateContext(func(logctx zerolog.Context) zerolog.Context {
				return logctx.Str("targetChannelName", nick)
			})

			cc, err := session.GuildChannelCreate(g.ID, nick, discordgo.ChannelTypeGuildText)
			if err != nil {
				logger.Error().
					Err(err).
					Msg("session.GuildChannelCreate")
				buf.WriteString("Error creating channel!")
				return
			}

			logger.UpdateContext(func(logctx zerolog.Context) zerolog.Context {
				return logctx.Str("targetChannelID", cc.ID)
			})

			if len(guild.PersonalChannelsParentID) != 0 {
				cc, err = session.ChannelEditComplex(cc.ID, &discordgo.ChannelEdit{
					ParentID: guild.PersonalChannelsParentID,
				})
				if err != nil {
					logger.Error().
						Err(err).
						Msg("session.ChannelEditComplex")
					session.ChannelDelete(cc.ID)
					buf.WriteString("Error creating channel!")
					return
				}
			}

			if guild.PersonalChannels == nil {
				guild.PersonalChannels = make(map[string]string)
			}
			guild.PersonalChannels[u.ID] = cc.ID
			logger.Info().
				Msg("personal create")
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
				logger.Error().
					Err(err).
					Msg("session.Channel")
				buf.WriteString("Error finding your personal channel!")
				return
			}

			logger.UpdateContext(func(logctx zerolog.Context) zerolog.Context {
				return logctx.
					Str("targetChannelID", cc.ID).
					Str("targetChannelName", cc.Name)
			})

			_, err = gHelper.ChannelDelete(cc.ID)
			if err != nil {
				logger.Error().
					Err(err).
					Msg("helper.ChannelDelete")
				buf.WriteString("Error deleting channel!")
				return
			}

			logger.Info().
				Msg("personal destroy")
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
			saveState(logger)
			logger.Info().
				Msg("parent")
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
			logger.Error().
				Err(err).
				Msg("helper.CategoryByArgument")
			buf.WriteString("Error while searching for category!")
			return
		}

		logger.UpdateContext(func(logctx zerolog.Context) zerolog.Context {
			return logctx.
				Str("targetCategoryID", cc.ID).
				Str("targetCategoryName", cc.Name)
		})

		guild.PersonalChannelsParentID = cc.ID
		saveState(logger)
		logger.Info().
			Msg("parent")
		fmt.Fprintf(&buf, "OK, from now on any personal channels I create will be children of %s.", cc.Name)
		return

	case ".debug":
		if trustedUser {
			logger.Info().
				Msg("debug")
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

func parseChan(buf *bytes.Buffer, logger *zerolog.Logger, c *discordgo.Channel, g *discordgo.Guild, arg string) (cid, msg string, valid bool) {
	logger.UpdateContext(func(logctx zerolog.Context) zerolog.Context {
		return logctx.Str("target", arg)
	})

	if arg == "" || arg == "any" {
		cid = ""
		msg = "on any channel"
		valid = true
		return
	}

	if arg == "this" {
		logger.UpdateContext(func(logctx zerolog.Context) zerolog.Context {
			return logctx.
				Str("targetChannelID", c.ID).
				Str("targetChannelName", c.Name)
		})
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
		logger.Error().
			Err(err).
			Msg("helper.ChannelByArgument")
		buf.WriteString("Error while searching for channel!")
		return
	}

	logger.UpdateContext(func(logctx zerolog.Context) zerolog.Context {
		return logctx.
			Str("targetChannelID", cc.ID).
			Str("targetChannelName", cc.Name)
	})

	cid = cc.ID
	msg = fmt.Sprintf("only on #%s", cc.Name)
	valid = true
	return
}

func parseRole(buf *bytes.Buffer, logger *zerolog.Logger, g *discordgo.Guild, arg string) (r *discordgo.Role, valid bool) {
	logger.UpdateContext(func(logctx zerolog.Context) zerolog.Context {
		return logctx.Str("target", arg)
	})

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
		logger.Error().
			Err(err).
			Msg("helper.RoleByArgument")
		buf.WriteString("Error while searching for role!")
		return
	}

	logger.UpdateContext(func(logctx zerolog.Context) zerolog.Context {
		return logctx.
			Str("targetRoleID", r.ID).
			Str("targetRoleName", r.Name)
	})

	valid = true
	return
}

func parseMember(buf *bytes.Buffer, logger *zerolog.Logger, g *discordgo.Guild, arg string) (m *discordgo.Member, valid bool) {
	logger.UpdateContext(func(logctx zerolog.Context) zerolog.Context {
		return logctx.Str("target", arg)
	})

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
		logger.Error().
			Err(err).
			Msg("helper.MemberByArgument")
		buf.WriteString("Error while searching for member!")
		return
	}

	u := m.User
	targetNick := m.Nick
	if targetNick == "" {
		targetNick = u.Username
	}

	logger.UpdateContext(func(logctx zerolog.Context) zerolog.Context {
		return logctx.
			Str("targetUserID", u.ID).
			Str("targetUserName", u.Username+"#"+u.Discriminator).
			Str("targetUserNick", targetNick)
	})

	valid = true
	return
}

func saveState(logger *zerolog.Logger) {
	raw, err := jsonMarshal(&gState)
	if err != nil {
		logger.Fatal().
			Err(err).
			Msg("json.Marshal")
	}

	err = ioutil.WriteFile(flagStateFile, raw, 0666)
	if err != nil {
		logger.Fatal().
			Err(err).
			Msg("ioutil.WriteFile")
	}
}

func isAuto(guild *botGuildState, r *discordgo.Role) bool {
	_, found := guild.Auto[r.ID]
	return found
}

func isTrusted(logger *zerolog.Logger, guild *botGuildState, g *discordgo.Guild, u *discordgo.User) bool {
	if u.ID == g.OwnerID {
		return true
	}
	if _, found := guild.TrustedUsers[u.ID]; found {
		return true
	}
	if len(guild.TrustedRoles) != 0 {
		member, err := gHelper.GuildMember(g.ID, u.ID)
		if err != nil {
			logger.Error().
				Err(err).
				Msg("helper.GuildMember")
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

// type logWriter {{{

type logWriter struct {
	fileName   string
	mu         sync.Mutex
	cv         *sync.Cond
	file       *os.File
	numWriters int
}

func newLogWriter(fileName string) (*logWriter, error) {
	file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	w := &logWriter{
		fileName:   fileName,
		file:       file,
		numWriters: 0,
	}
	w.cv = sync.NewCond(&w.mu)
	return w, nil
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	file := w.file
	w.numWriters++
	w.mu.Unlock()

	defer func() {
		w.mu.Lock()
		w.numWriters--
		if w.numWriters <= 0 {
			w.cv.Signal()
		}
		w.mu.Unlock()
	}()

	return file.Write(p)
}

func (w *logWriter) Close() error {
	w.mu.Lock()
	defer func() {
		w.cv.Signal()
		w.mu.Unlock()
	}()

	for w.numWriters > 0 {
		w.cv.Wait()
	}

	var errs []error
	if err := w.file.Sync(); err != nil {
		errs = append(errs, err)
	}
	if err := w.file.Close(); err != nil {
		errs = append(errs, err)
	}
	return errorOrNil(errs)
}

func (w *logWriter) Rotate() error {
	newFile, err := os.OpenFile(w.fileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return err
	}

	w.mu.Lock()
	defer func() {
		w.cv.Signal()
		w.mu.Unlock()
	}()

	for w.numWriters > 0 {
		w.cv.Wait()
	}

	oldFile := w.file
	w.file = newFile

	var errs []error
	if e := oldFile.Sync(); e != nil {
		errs = append(errs, e)
	}
	if e := oldFile.Close(); e != nil {
		errs = append(errs, e)
	}
	return errorOrNil(errs)
}

var _ io.WriteCloser = (*logWriter)(nil)

// }}}

func errorOrNil(errs []error) error {
	length := uint(len(errs))

	if length == 0 {
		return nil
	}

	if length == 1 {
		_, ok := errs[0].(*multierror.Error)
		if !ok {
			return errs[0]
		}
	}

	clone := &multierror.Error{
		Errors:      errs,
		ErrorFormat: nil,
	}
	flattenErrors(clone, errs)
	return clone
}

func flattenErrors(out *multierror.Error, errs []error) {
	for _, e := range errs {
		switch x := e.(type) {
		case *multierror.Error:
			flattenErrors(out, x.Errors)
		default:
			out.Errors = append(out.Errors, e)
		}
	}
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
