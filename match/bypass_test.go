package match

import (
	"context"
	"testing"

	"github.com/alwitt/padlock/common"
	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
)

func TestBypassMethodMatcher(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)
	utCtxt := context.Background()

	uut, err := defineBypassMethodMatcher([]string{"GET", "post", "DELete"})
	assert.Nil(err)

	match, err := uut.Match(utCtxt, RequestParam{Method: "get"})
	assert.Nil(err)
	assert.True(match)

	match, err = uut.Match(utCtxt, RequestParam{Method: "put"})
	assert.Nil(err)
	assert.False(match)

	match, err = uut.Match(utCtxt, RequestParam{Method: "DELETE"})
	assert.Nil(err)
	assert.True(match)
}

func TestBypassHostMatcher(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)
	utCtxt := context.Background()

	uut, err := defineBypassHostMatcher([]string{"unit-test.testing.org", "my-site.dev.org"})
	assert.Nil(err)

	host := "unit-test.testing.org"
	match, err := uut.Match(utCtxt, RequestParam{Host: &host})
	assert.Nil(err)
	assert.True(match)

	host = "test.testing.org"
	match, err = uut.Match(utCtxt, RequestParam{Host: &host})
	assert.Nil(err)
	assert.False(match)

	host = "my-SITE.dev.ORG"
	match, err = uut.Match(utCtxt, RequestParam{Host: &host})
	assert.Nil(err)
	assert.True(match)
}

func TestBypassURIPathMatcher(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)
	utCtxt := context.Background()

	uut, err := defineBypassPathMatcher(
		[]string{`^/public/[\w\d]+/index\.html$`, `^/public/[\d-]+/`},
	)
	assert.Nil(err)

	match, err := uut.Match(utCtxt, RequestParam{Path: "/public/store/index.html"})
	assert.Nil(err)
	assert.True(match)

	match, err = uut.Match(utCtxt, RequestParam{Path: "/public/dev-pub/index.html"})
	assert.Nil(err)
	assert.False(match)

	match, err = uut.Match(utCtxt, RequestParam{Path: "/public/919-886-7134/meta.json"})
	assert.Nil(err)
	assert.True(match)
}

func TestAuthBypassMatcher(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)
	utCtxt := context.Background()

	uut, err := DefineAuthBypassMatch(common.AuthnBypassConfig{
		Rules: []common.AuthnBypassMatchEntry{
			{MatchType: "method", Matches: []string{"GET", "post"}},
			{MatchType: "method", Matches: []string{"DELete"}},
			{MatchType: "host", Matches: []string{"unit-test.testing.org", "my-site.dev.org"}},
			{MatchType: "path", Matches: []string{`^/public/[\w\d]+/index\.html$`, `^/public/[\d-]+/`}},
		},
	})
	assert.Nil(err)

	match, err := uut.Match(utCtxt, RequestParam{Method: "get"})
	assert.Nil(err)
	assert.True(match)

	match, err = uut.Match(utCtxt, RequestParam{Method: "put"})
	assert.Nil(err)
	assert.False(match)

	match, err = uut.Match(utCtxt, RequestParam{Method: "DELETE"})
	assert.Nil(err)
	assert.True(match)

	host := "unit-test.testing.org"
	match, err = uut.Match(utCtxt, RequestParam{Host: &host})
	assert.Nil(err)
	assert.True(match)

	host = "test.testing.org"
	match, err = uut.Match(utCtxt, RequestParam{Host: &host})
	assert.Nil(err)
	assert.False(match)

	host = "my-SITE.dev.ORG"
	match, err = uut.Match(utCtxt, RequestParam{Host: &host})
	assert.Nil(err)
	assert.True(match)

	match, err = uut.Match(utCtxt, RequestParam{Path: "/public/store/index.html"})
	assert.Nil(err)
	assert.True(match)

	match, err = uut.Match(utCtxt, RequestParam{Path: "/public/dev-pub/index.html"})
	assert.Nil(err)
	assert.False(match)

	match, err = uut.Match(utCtxt, RequestParam{Path: "/public/919-886-7134/meta.json"})
	assert.Nil(err)
	assert.True(match)
}
