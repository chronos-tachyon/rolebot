package bothelper

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"

	"github.com/bwmarrin/discordgo"
)

const (
	MaxMembersPerFetch = 1000
)

var (
	ErrNotFound  = errors.New("not found")
	ErrManyFound = errors.New("many found")
)

var (
	reChannelRef = regexp.MustCompile(`^<#([0-9]+)>$`)
	reRoleRef    = regexp.MustCompile(`^<@&([0-9]+)>$`)
	reMemberRef  = regexp.MustCompile(`^<@([0-9]+)>$`)
)

func Fold(s string) string {
	b := []byte(s)
	b = bytes.ToLower(b)
	b = bytes.TrimLeft(b, "#@:")
	b = bytes.TrimSpace(b)
	return string(b)
}

func IsMatchingNick(nick string, m *discordgo.Member) bool {
	var k1, k2, k3 string
	k1 = Fold(nick)
	if m.Nick == "" {
		k2 = Fold(m.User.Username)
	} else {
		k2 = Fold(m.Nick)
	}
	k3 = Fold(fmt.Sprintf("%s#%s", m.User.Username, m.User.Discriminator))
	return (k1 == k2 || k1 == k3)
}

type BotHelper struct {
	*discordgo.Session
}

func New(session *discordgo.Session) *BotHelper {
	return &BotHelper{session}
}

func (h *BotHelper) Me() *discordgo.User {
	h.Session.State.RLock()
	defer h.Session.State.RUnlock()
	return h.Session.State.User
}

func (h *BotHelper) GuildById(id string) (*discordgo.Guild, error) {
	g, err := h.Session.State.Guild(id)
	if err == nil {
		return g, nil
	}

	g, err = h.Session.Guild(id)
	if err != nil {
		return nil, fmt.Errorf("Guild: %v", err)
	}

	// TODO: no such guild -> ErrNotFound
	return g, nil
}

func (h *BotHelper) ChannelById(id string) (*discordgo.Channel, error) {
	c, err := h.Session.State.Channel(id)
	if err == nil {
		return c, nil
	}

	c, err = h.Session.Channel(id)
	if err != nil {
		return nil, fmt.Errorf("Channel: %v", err)
	}

	// TODO: no such channel -> ErrNotFound
	return c, nil
}

func (h *BotHelper) ChannelByName(gid, name string) (*discordgo.Channel, error) {
	k1 := Fold(name)

	var result *discordgo.Channel
	var found uint = 0

	h.Session.State.RLock()
	for _, g := range h.Session.State.Guilds {
		if g.ID != gid {
			continue
		}
		for _, c := range g.Channels {
			k2 := Fold(c.Name)
			if k1 == k2 {
				result = c
				found += 1
			}
		}
	}
	h.Session.State.RUnlock()

	if found == 0 {
		channels, err := h.Session.GuildChannels(gid)
		if err != nil {
			return nil, fmt.Errorf("GuildChannels: %v", err)
		}

		for _, c := range channels {
			k2 := Fold(c.Name)
			if k1 == k2 {
				result = c
				found += 1
			}
		}
	}

	if found == 1 {
		return result, nil
	}
	if found != 0 {
		return result, ErrManyFound
	}
	return nil, ErrNotFound
}

func (h *BotHelper) ChannelByArgument(gid, arg string) (*discordgo.Channel, error) {
	match := reChannelRef.FindStringSubmatch(arg)
	if len(match) == 2 {
		return h.ChannelById(match[1])
	}
	return h.ChannelByName(gid, arg)
}

func (h *BotHelper) RoleById(gid, rid string) (*discordgo.Role, error) {
	r, err := h.Session.State.Role(gid, rid)
	if err == nil {
		return r, nil
	}

	roles, err := h.Session.GuildRoles(gid)
	if err != nil {
		return nil, fmt.Errorf("GuildRoles: %v", err)
	}

	for _, r = range roles {
		if r.ID == rid {
			return r, nil
		}
	}
	return nil, ErrNotFound
}

func (h *BotHelper) RoleByName(gid, name string) (*discordgo.Role, error) {
	k1 := Fold(name)

	var result *discordgo.Role
	var found uint = 0

	h.Session.State.RLock()
	for _, g := range h.Session.State.Guilds {
		if g.ID != gid {
			continue
		}
		for _, r := range g.Roles {
			k2 := Fold(r.Name)
			if k1 == k2 {
				result = r
				found += 1
			}
		}
	}
	h.Session.State.RUnlock()

	if found == 0 {
		roles, err := h.Session.GuildRoles(gid)
		if err != nil {
			return nil, fmt.Errorf("GuildRoles: %v", err)
		}

		for _, r := range roles {
			k2 := Fold(r.Name)
			if k1 == k2 {
				result = r
				found += 1
			}
		}
	}

	if found == 1 {
		return result, nil
	}
	if found != 0 {
		return result, ErrManyFound
	}
	return nil, ErrNotFound
}

func (h *BotHelper) RoleByArgument(gid, arg string) (*discordgo.Role, error) {
	match := reRoleRef.FindStringSubmatch(arg)
	if len(match) == 2 {
		return h.RoleById(gid, match[1])
	}
	return h.RoleByName(gid, arg)
}

func (h *BotHelper) MemberById(gid, uid string) (*discordgo.Member, error) {
	m, err := h.Session.State.Member(gid, uid)
	if err == nil {
		return m, nil
	}

	m, err = h.Session.GuildMember(gid, uid)
	if err != nil {
		return nil, fmt.Errorf("GuildMember: %v", err)
	}

	// TODO: no such member -> ErrNotFound
	return m, nil
}

func (h *BotHelper) MemberByName(gid, name string) (*discordgo.Member, error) {
	k1 := Fold(name)

	var result *discordgo.Member
	var found uint = 0

	h.Session.State.RLock()
	for _, g := range h.Session.State.Guilds {
		if g.ID != gid {
			continue
		}
		for _, m := range g.Members {
			if IsMatchingNick(k1, m) {
				result = m
				found += 1
			}
		}
	}
	h.Session.State.RUnlock()

	if found == 0 {
		// TODO: figure out the API for paginated results
		members, err := h.Session.GuildMembers(gid, "", MaxMembersPerFetch)
		if err != nil {
			return nil, fmt.Errorf("GuildMembers: %v", err)
		}
		for _, m := range members {
			if IsMatchingNick(k1, m) {
				result = m
				found += 1
			}
		}
	}

	if found == 1 {
		return result, nil
	}
	if found != 0 {
		return result, ErrManyFound
	}
	return nil, ErrNotFound
}

func (h *BotHelper) MemberByArgument(gid, arg string) (*discordgo.Member, error) {
	match := reMemberRef.FindStringSubmatch(arg)
	if len(match) == 2 {
		return h.MemberById(gid, match[1])
	}
	return h.MemberByName(gid, arg)
}
