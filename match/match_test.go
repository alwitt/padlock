package match

import (
	"testing"

	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
)

func TestRegexCheck(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	type testCase struct {
		input string
		match bool
	}

	// Case 0: basic path
	{
		cases := []testCase{
			{input: "/path", match: true},
			{input: "/paths", match: false},
			{input: "hello", match: false},
		}
		uut, err := NewRegexCheck("^/path$")
		assert.Nil(err)
		for _, aTest := range cases {
			m, err := uut.Match([]byte(aTest.input))
			assert.Nil(err)
			assert.Equalf(aTest.match, m, aTest.input)
		}
	}

	// Case 1: path prefix
	{
		cases := []testCase{
			{input: "/path", match: true},
			{input: "/paths", match: true},
			{input: "hello", match: false},
		}
		uut, err := NewRegexCheck("^/path")
		assert.Nil(err)
		for _, aTest := range cases {
			m, err := uut.Match([]byte(aTest.input))
			assert.Nil(err)
			assert.Equalf(aTest.match, m, aTest.input)
		}
	}

	// Case 2: path parameter in middle
	{
		cases := []testCase{
			{input: "/path", match: false},
			{input: "/path/jwf944", match: true},
			{input: "/path/jwf944/", match: true},
			{input: "/path/jwf944//", match: false},
			{input: "hello", match: false},
			{input: "/path/jwf944/path2", match: false},
		}
		uut, err := NewRegexCheck(`^/path/\w+/{0,1}$`)
		assert.Nil(err)
		for _, aTest := range cases {
			m, err := uut.Match([]byte(aTest.input))
			assert.Nil(err)
			assert.Equalf(aTest.match, m, aTest.input)
		}
	}

	// Case 3: multiple path parameter in middle
	{
		cases := []testCase{
			{input: "/path", match: false},
			{input: "/path/jwf944", match: false},
			{input: "/path/jwf944/", match: false},
			{input: "/path/jwf944//", match: false},
			{input: "hello", match: false},
			{input: "/path1/jwf944/path2/89qf23", match: true},
			{input: "/path1/jwf944/path/89qf23", match: false},
			{input: "/path1/jwf944/path2/.(*0#", match: false},
			{input: "/path1/jwf944/path2/89qf23/", match: true},
			{input: "/path1//jwf944/path2/89qf23/", match: false},
			{input: "/path1/jwf944/path2/89qf23//", match: false},
		}
		uut, err := NewRegexCheck(`^/path1/\w+/path2/\w+/{0,1}$`)
		assert.Nil(err)
		for _, aTest := range cases {
			m, err := uut.Match([]byte(aTest.input))
			assert.Nil(err)
			assert.Equalf(aTest.match, m, aTest.input)
		}
	}

	// Case 4: path parameter at start of path
	{
		cases := []testCase{
			{input: "/q48ma8/path", match: true},
			{input: "/path", match: false},
			{input: "/path/path/", match: true},
		}
		uut, err := NewRegexCheck(`^/\w+/path/{0,1}$`)
		assert.Nil(err)
		for _, aTest := range cases {
			m, err := uut.Match([]byte(aTest.input))
			assert.Nil(err)
			assert.Equalf(aTest.match, m, aTest.input)
		}
	}

	// Case 5: path parameter support UUID or alphanumeric + "."
	{
		cases := []testCase{
			{input: "/path/2b44aafc-544e-45a0-bfd5-9018cae4849d", match: true},
			{input: "/path/this.is.valid", match: true},
			{input: "/path/this-is.not.valid", match: false},
			{input: "/path/this.is,not.valid", match: false},
			{input: "/path/not.valid.2b44aafc-544e-45a0-bfd5-9018cae4849d", match: false},
		}
		uut, err := NewRegexCheck(
			`^/path/([\w\.]+|[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12})/{0,1}$`,
		)
		assert.Nil(err)
		for _, aTest := range cases {
			m, err := uut.Match([]byte(aTest.input))
			assert.Nil(err)
			assert.Equalf(aTest.match, m, aTest.input)
		}
	}
}
