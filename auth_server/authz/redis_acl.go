package authz

import (
	"errors"
	"fmt"
	"strings"

	"github.com/golang/glog"
	"github.com/mediocregopher/radix.v2/pool"
)

type aclRedisAuthorizer struct {
	pool       *pool.Pool
	ServerAddr string
	KeyPrefix  string
}

func NewACLRedisAuthorizer(addr string, keyPrefix string) Authorizer {
	return &aclRedisAuthorizer{
		ServerAddr: addr,
		KeyPrefix:  keyPrefix,
	}
}

func (aa *aclRedisAuthorizer) Connect() error {
	var err error
	aa.pool, err = pool.New("tcp", aa.ServerAddr, 10)

	if err != nil {
		return err
	}

	return nil
}

func parse(acl string) (ACLEntry, error) {
	// repository:distribution/registry:pull
	// repository:library/image-*:pull,push

	parts := strings.Split(acl, ":")

	// Remove empty parts
	_parts := []string{}
	for i := range parts {
		if parts[i] != "" {
			_parts = append(_parts, parts[i])
		}
	}
	parts = _parts

	if len(parts) != 3 {
		return ACLEntry{}, errors.New("Malformed ACL entry: " + acl)
	}

	perms := strings.Split(parts[2], ",")
	return ACLEntry{
		Match: &MatchConditions{
			Type: &parts[0],
			Name: &parts[1],
		},
		Actions: &perms,
	}, nil
}

func (aa *aclRedisAuthorizer) Authorize(ai *AuthRequestInfo) ([]string, error) {
	client, err := aa.pool.Get()
	if err != nil {
		return nil, err
	}
	defer aa.pool.Put(client)

	acls, err := client.Cmd("smembers", fmt.Sprintf("%s%s:%s", aa.KeyPrefix, "acl", ai.Account)).Array()
	if err != nil {
		return nil, err
	}

	entries := []ACLEntry{}
	for i := range acls {
		if a, err := acls[i].Str(); err == nil {
			acl, err := parse(a)
			if err == nil {
				entries = append(entries, acl)
			}
		}
	}

	matchedActions := redisACLMatches(entries, ai)
	if len(matchedActions) > 0 {
		return matchedActions, nil
	}

	return nil, NoMatch
}

func (aa *aclRedisAuthorizer) Stop() {
	aa.pool.Empty()
}

func (aa *aclRedisAuthorizer) Name() string {
	return "redis ACL"
}

func redisACLMatches(entries []ACLEntry, ai *AuthRequestInfo) []string {
	factions := []string{}

	for _, e := range entries {
		matched := e.Matches(ai)
		if matched {
			glog.V(2).Infof("%s matched %s", ai, e)
			a := StringSetIntersection(ai.Actions, *e.Actions)

			// Choose matching with more actions
			if len(a) > len(factions) {
				factions = a
			}
		}
	}

	return factions
}

/*
func (e *ACLEntry) Matches(ai *AuthRequestInfo) bool {
	if matchString(e.Match.Type, ai.Type) &&
		matchString(e.Match.Name, ai.Name) {
		return true
	}
	return false
}*/
