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
		input    string
		testFunc func(err error)
	}

	// Case 0: basic path
	{
		cases := []testCase{
			{input: "/path", testFunc: func(err error) {
				assert.Nilf(err, "/path")
			}},
			{input: "/paths", testFunc: func(err error) {
				assert.NotNilf(err, "/paths")
			}},
			{input: "hello", testFunc: func(err error) {
				assert.NotNilf(err, "hello")
			}},
		}
		uut, err := NewRegexCheck("^/path$")
		assert.Nil(err)
		for _, aTest := range cases {
			aTest.testFunc(uut.Match([]byte(aTest.input)))
		}
	}

	// Case 1: path prefix
	{
		cases := []testCase{
			{input: "/path", testFunc: func(err error) {
				assert.Nilf(err, "/path")
			}},
			{input: "/paths", testFunc: func(err error) {
				assert.Nilf(err, "/paths")
			}},
			{input: "hello", testFunc: func(err error) {
				assert.NotNilf(err, "hello")
			}},
		}
		uut, err := NewRegexCheck("^/path")
		assert.Nil(err)
		for _, aTest := range cases {
			aTest.testFunc(uut.Match([]byte(aTest.input)))
		}
	}

	// Case 2: path parameter in middle
	{
		cases := []testCase{
			{input: "/path", testFunc: func(err error) {
				assert.NotNilf(err, "/path")
			}},
			{input: "/path/jwf944", testFunc: func(err error) {
				assert.Nilf(err, "/path/jwf944")
			}},
			{input: "/path/jwf944/", testFunc: func(err error) {
				assert.Nilf(err, "/path/jwf944/")
			}},
			{input: "/path/jwf944//", testFunc: func(err error) {
				assert.NotNilf(err, "/path/jwf944//")
			}},
			{input: "hello", testFunc: func(err error) {
				assert.NotNilf(err, "hello")
			}},
			{input: "/path/jwf944/path2", testFunc: func(err error) {
				assert.NotNilf(err, "/path/jwf944/path2")
			}},
		}
		uut, err := NewRegexCheck(`^/path/\w+/{0,1}$`)
		assert.Nil(err)
		for _, aTest := range cases {
			aTest.testFunc(uut.Match([]byte(aTest.input)))
		}
	}

	// Case 3: multiple path parameter in middle
	{
		cases := []testCase{
			{input: "/path", testFunc: func(err error) {
				assert.NotNilf(err, "/path")
			}},
			{input: "/path/jwf944", testFunc: func(err error) {
				assert.NotNilf(err, "/path/jwf944")
			}},
			{input: "/path/jwf944/", testFunc: func(err error) {
				assert.NotNilf(err, "/path/jwf944/")
			}},
			{input: "/path/jwf944//", testFunc: func(err error) {
				assert.NotNilf(err, "/path/jwf944//")
			}},
			{input: "hello", testFunc: func(err error) {
				assert.NotNilf(err, "hello")
			}},
			{input: "/path1/jwf944/path2/89qf23", testFunc: func(err error) {
				assert.Nilf(err, "/path1/jwf944/path2/89qf23")
			}},
			{input: "/path1/jwf944/path/89qf23", testFunc: func(err error) {
				assert.NotNilf(err, "/path1/jwf944/path/89qf23")
			}},
			{input: "/path1/jwf944/path2/.(*0#", testFunc: func(err error) {
				assert.NotNilf(err, "/path1/jwf944/path2/.(*0#")
			}},
			{input: "/path1/jwf944/path2/89qf23/", testFunc: func(err error) {
				assert.Nilf(err, "/path1/jwf944/path2/89qf23/")
			}},
			{input: "/path1//jwf944/path2/89qf23/", testFunc: func(err error) {
				assert.NotNilf(err, "/path1//jwf944/path2/89qf23/")
			}},
			{input: "/path1/jwf944/path2/89qf23//", testFunc: func(err error) {
				assert.NotNilf(err, "/path1/jwf944/path2/89qf23//")
			}},
		}
		uut, err := NewRegexCheck(`^/path1/\w+/path2/\w+/{0,1}$`)
		assert.Nil(err)
		for _, aTest := range cases {
			aTest.testFunc(uut.Match([]byte(aTest.input)))
		}
	}

	// Case 4: path parameter at start of path
	{
		cases := []testCase{
			{input: "/q48ma8/path", testFunc: func(err error) {
				assert.Nilf(err, "/q48ma8/path")
			}},
			{input: "/path", testFunc: func(err error) {
				assert.NotNilf(err, "/path")
			}},
			{input: "/path/path/", testFunc: func(err error) {
				assert.Nilf(err, "/path/path/")
			}},
		}
		uut, err := NewRegexCheck(`^/\w+/path/{0,1}$`)
		assert.Nil(err)
		for _, aTest := range cases {
			aTest.testFunc(uut.Match([]byte(aTest.input)))
		}
	}

	// Case 5: path parameter support UUID or alphanumeric + "."
	{
		cases := []testCase{
			{input: "/path/2b44aafc-544e-45a0-bfd5-9018cae4849d", testFunc: func(err error) {
				assert.Nilf(err, "/path/2b44aafc-544e-45a0-bfd5-9018cae4849d")
			}},
			{input: "/path/this.is.valid", testFunc: func(err error) {
				assert.Nilf(err, "/path/this.is.valid")
			}},
			{input: "/path/this-is.not.valid", testFunc: func(err error) {
				assert.NotNilf(err, "/path/this-is.not.valid")
			}},
			{input: "/path/this.is,not.valid", testFunc: func(err error) {
				assert.NotNilf(err, "/path/this.is,not.valid")
			}},
			{input: "/path/not.valid.2b44aafc-544e-45a0-bfd5-9018cae4849d", testFunc: func(err error) {
				assert.NotNilf(err, "/path/not.valid.2b44aafc-544e-45a0-bfd5-9018cae4849d")
			}},
		}
		uut, err := NewRegexCheck(
			`^/path/([\w\.]+|[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12})/{0,1}$`,
		)
		assert.Nil(err)
		for _, aTest := range cases {
			aTest.testFunc(uut.Match([]byte(aTest.input)))
		}
	}
}
