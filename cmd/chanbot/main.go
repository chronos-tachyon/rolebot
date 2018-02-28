package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/bwmarrin/discordgo"
	log "github.com/sirupsen/logrus"

	"github.com/chronos-tachyon/rolebot/internal/bothelper"
)

var (
	flagJSON      = flag.Bool("json", false, "Write JSON to log file")
	flagLogfile   = flag.String("logfile", "", "Path to log file")
	flagTokenFile = flag.String("tokenfile", "", "Path to text file containing bot token")
)

var (
	reSpace   = regexp.MustCompile(`\s+`)
	reCommand = regexp.MustCompile(`^\.(create|destroy)\s*$`)
)

const (
	maxMembersPerFetch = 1000
)

var (
	gHelper *bothelper.BotHelper
	gLogMu  sync.Mutex
	gLog    *os.File
)

func main() {
	flag.Parse()
	sighup()

	raw, err := ioutil.ReadFile(*flagTokenFile)
	if err != nil {
		log.WithError(err).Fatal("ioutil.ReadFile")
	}
	token := "Bot " + string(bytes.TrimRight(raw, "\r\n"))

	session, err := discordgo.New(token)
	if err != nil {
		log.WithError(err).Fatal("discordgo.New")
	}
	session.ShouldReconnectOnError = true
	session.StateEnabled = true
	session.SyncEvents = false
	session.AddHandler(onMessage)

	gHelper = bothelper.New(session)

	err = session.Open()
	if err != nil {
		log.WithError(err).Fatal("session.Open")
	}
	defer session.Close()

	mainLoop()
}

func mainLoop() {
	log.Info("ChanBot is now running. Press Ctrl-C to exit.")

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt, os.Kill, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigch)

	for {
		sig := <-sigch
		log.WithField("sig", sig).Info("got signal")
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

	var formatter log.Formatter
	if *flagJSON {
		formatter = &log.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05Z0700",
			FieldMap: log.FieldMap{
				log.FieldKeyTime:  "@timestamp",
				log.FieldKeyLevel: "@level",
				log.FieldKeyMsg:   "@message",
			},
		}
	} else {
		formatter = &log.TextFormatter{
			TimestampFormat: "2006-01-02 15:04:05 Z0700",
		}
	}

	if len(*flagLogfile) == 0 {
		log.SetFormatter(formatter)
		log.SetLevel(log.InfoLevel)
		return
	}

	f, err := os.OpenFile(*flagLogfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.WithError(err).Fatal("os.OpenFile")
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	log.SetFormatter(formatter)
	log.SetLevel(log.InfoLevel)
	log.SetOutput(f)
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
	messageContent = strings.TrimSuffix(messageContent, " ")

	match := reCommand.FindStringSubmatch(messageContent)
	if len(match) == 0 {
		return
	}
	command := match[1]

	fields := log.Fields{
		"command":          command,
		"messageContent":   message.Content,
		"messageAuthorID":  message.Author.ID,
		"messageChannelID": message.ChannelID,
	}

	c, err := gHelper.ChannelById(message.ChannelID)
	if err != nil {
		log.WithError(err).WithFields(fields).Error("helper.ChannelById")
		return
	}
	fields["messageChannelName"] = c.Name

	g, err := gHelper.GuildById(c.GuildID)
	if err != nil {
		log.WithError(err).WithFields(fields).Error("helper.GuildById")
		return
	}
	fields["messageGuildID"] = g.ID

	m, err := gHelper.MemberById(g.ID, message.Author.ID)
	if err != nil {
		log.WithError(err).WithFields(fields).Error("helper.MemberById")
		return
	}

	nick := m.Nick
	if nick == "" {
		nick = m.User.Username
	}
	fields["messageUser"] = message.Author.Username + "#" + message.Author.Discriminator
	fields["messageNick"] = nick

	var buf bytes.Buffer
	buf.WriteString(u.Mention())

	defer func() {
		if buf.Len() == 0 {
			return
		}
		str := buf.String()
		fields["replyText"] = str
		_, err := session.ChannelMessageSend(message.ChannelID, str)
		if err != nil {
			log.WithError(err).WithFields(fields).Error("session.ChannelMessageSend")
		}
	}()

	switch command {
	case "create":
		cc, err := gHelper.GuildChannelCreate(g.ID, nick, "text")
		if err != nil {
			log.WithError(err).WithFields(fields).Error("helper.GuildChannelCreate")
			buf.WriteString(" Error creating channel!")
			return
		}

		log.WithFields(fields).Info("channel create")
		fmt.Fprintf(&buf, " OK, I created your channel. %s", channelMention(cc))

	case "destroy":
		cc, err := gHelper.ChannelByName(g.ID, nick)
		if err == bothelper.ErrNotFound {
			buf.WriteString(" Could not find a channel with your name!")
			return
		} else if err == bothelper.ErrManyFound {
			buf.WriteString(" Found multiple channels with your name!")
			return
		} else if err != nil {
			log.WithError(err).WithFields(fields).Error("helper.ChannelByName")
			buf.WriteString(" Error finding existing channel!")
			return
		}

		fields["existingChannelID"] = cc.ID
		fields["existingChannelName"] = cc.Name
		_, err = gHelper.ChannelDelete(cc.ID)
		if err != nil {
			log.WithError(err).WithFields(fields).Error("helper.ChannelDelete")
			buf.WriteString(" Error deleting channel!")
			return
		}

		log.WithFields(fields).Info("channel delete")
		buf.WriteString(" OK, I deleted your channel.")

	default:
		log.WithFields(fields).Error("unknown command")
		buf.WriteString(" I didn't understand that.")
	}
}

func channelMention(c *discordgo.Channel) string {
	return fmt.Sprintf("<#%s>", c.ID)
}
