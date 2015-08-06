package authz

import (
	"reflect"
	"testing"
)

var repository = strAddr("repository")

var validACLs = map[string]ACLEntry{
	"repository:centos:pull": ACLEntry{
		Match: &MatchConditions{
			Type: repository,
			Name: strAddr("centos"),
		},
		Actions: &[]string{
			"pull",
		},
	},
	"repository:centos:pull,push": ACLEntry{
		Match: &MatchConditions{
			Type: repository,
			Name: strAddr("centos"),
		},
		Actions: &[]string{
			"pull",
			"push",
		},
	},
	"repository:library/centos:pull": ACLEntry{
		Match: &MatchConditions{
			Type: repository,
			Name: strAddr("library/centos"),
		},
		Actions: &[]string{
			"pull",
		},
	},
	"repository:cloud/*:pull": ACLEntry{
		Match: &MatchConditions{
			Type: repository,
			Name: strAddr("cloud/*"),
		},
		Actions: &[]string{
			"pull",
		},
	},
	"repository:*:pull,push": ACLEntry{
		Match: &MatchConditions{
			Type: repository,
			Name: strAddr("*"),
		},
		Actions: &[]string{
			"pull",
			"push",
		},
	},
	"repository:golang*:push": ACLEntry{
		Match: &MatchConditions{
			Type: repository,
			Name: strAddr("golang*"),
		},
		Actions: &[]string{
			"push",
		},
	},
	"repository:open/consul_*:pull": ACLEntry{
		Match: &MatchConditions{
			Type: repository,
			Name: strAddr("open/consul_*"),
		},
		Actions: &[]string{
			"pull",
		},
	},
}

var invalidACLs = []string{
	"repository",
	"repository:redis",
	"repository:redis:",
	"repository::pull",
}

func strAddr(str string) *string {
	s := str
	return &s
}

func TestValidACLs(t *testing.T) {
	for key, vent := range validACLs {
		ent, err := parse(key)
		if err != nil {
			t.Errorf("Failed to parse %s", key)
		}
		if reflect.DeepEqual(ent, vent) == false {
			t.Errorf("Failed to convert %s to ACL entry", key)
		}
	}
}

func TestInvalidACLs(t *testing.T) {
	for i := range invalidACLs {
		_, err := parse(invalidACLs[i])
		if err == nil {
			t.Errorf("Should have failed to parse %s", invalidACLs[i])
		}
	}
}

var singleUserACL = []string{
	"repository:cloud/*:pull",
	"repository:cloud/centos_6.5:pull,push",
}

func TestSingleUserACL(t *testing.T) {
	authz := AuthRequestInfo{
		Type: "repository",
		Name: "cloud/centos_6.5",
	}

	entities := []ACLEntry{}
	for i := range singleUserACL {
		ent, _ := parse(singleUserACL[i])
		entities = append(entities, ent)
	}
	matches := redisACLMatches(entities, &authz)
	if reflect.DeepEqual(matches, []string{"pull", "push"}) != false {
		t.Errorf("Expected push,pull but got %s", matches)
	}

}
