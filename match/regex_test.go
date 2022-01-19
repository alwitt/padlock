package match

import (
	"regexp"
	"testing"

	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
)

func TestRegrexBehaviour(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	type testCase struct {
		input    string
		testFunc func(s []byte)
	}

	// Case 0: basic path
	{
		cases := []testCase{
			{input: "/path", testFunc: func(s []byte) {
				assert.NotNilf(s, "/path")
			}},
			{input: "/paths", testFunc: func(s []byte) {
				assert.Nilf(s, "/paths")
			}},
			{input: "hello", testFunc: func(s []byte) {
				assert.Nilf(s, "hello")
			}},
		}
		reg, err := regexp.Compile("^/path$")
		assert.Nil(err)
		for _, aTest := range cases {
			aTest.testFunc(reg.Find([]byte(aTest.input)))
		}
	}

	// Case 1: path prefix
	{
		cases := []testCase{
			{input: "/path", testFunc: func(s []byte) {
				assert.NotNilf(s, "/path")
			}},
			{input: "/paths", testFunc: func(s []byte) {
				assert.NotNilf(s, "/paths")
			}},
			{input: "hello", testFunc: func(s []byte) {
				assert.Nilf(s, "hello")
			}},
		}
		reg, err := regexp.Compile("^/path")
		assert.Nil(err)
		for _, aTest := range cases {
			aTest.testFunc(reg.Find([]byte(aTest.input)))
		}
	}

	// Case 2: path parameter in middle
	{
		cases := []testCase{
			{input: "/path", testFunc: func(s []byte) {
				assert.Nilf(s, "/path")
			}},
			{input: "/path/jwf944", testFunc: func(s []byte) {
				assert.NotNilf(s, "/path/jwf944")
			}},
			{input: "/path/jwf944/", testFunc: func(s []byte) {
				assert.NotNilf(s, "/path/jwf944/")
			}},
			{input: "/path/jwf944//", testFunc: func(s []byte) {
				assert.Nilf(s, "/path/jwf944//")
			}},
			{input: "hello", testFunc: func(s []byte) {
				assert.Nilf(s, "hello")
			}},
			{input: "/path/jwf944/path2", testFunc: func(s []byte) {
				assert.Nilf(s, "/path/jwf944/path2")
			}},
		}
		reg, err := regexp.Compile(`^/path/\w+/{0,1}$`)
		assert.Nil(err)
		for _, aTest := range cases {
			aTest.testFunc(reg.Find([]byte(aTest.input)))
		}
	}

	// Case 3: multiple path parameter in middle
	{
		cases := []testCase{
			{input: "/path", testFunc: func(s []byte) {
				assert.Nilf(s, "/path")
			}},
			{input: "/path/jwf944", testFunc: func(s []byte) {
				assert.Nilf(s, "/path/jwf944")
			}},
			{input: "/path/jwf944/", testFunc: func(s []byte) {
				assert.Nilf(s, "/path/jwf944/")
			}},
			{input: "/path/jwf944//", testFunc: func(s []byte) {
				assert.Nilf(s, "/path/jwf944//")
			}},
			{input: "hello", testFunc: func(s []byte) {
				assert.Nilf(s, "hello")
			}},
			{input: "/path1/jwf944/path2/89qf23", testFunc: func(s []byte) {
				assert.NotNilf(s, "/path1/jwf944/path2/89qf23")
			}},
			{input: "/path1/jwf944/path/89qf23", testFunc: func(s []byte) {
				assert.Nilf(s, "/path1/jwf944/path/89qf23")
			}},
			{input: "/path1/jwf944/path2/.(*0#", testFunc: func(s []byte) {
				assert.Nilf(s, "/path1/jwf944/path2/.(*0#")
			}},
			{input: "/path1/jwf944/path2/89qf23/", testFunc: func(s []byte) {
				assert.NotNilf(s, "/path1/jwf944/path2/89qf23/")
			}},
			{input: "/path1//jwf944/path2/89qf23/", testFunc: func(s []byte) {
				assert.Nilf(s, "/path1//jwf944/path2/89qf23/")
			}},
			{input: "/path1/jwf944/path2/89qf23//", testFunc: func(s []byte) {
				assert.Nilf(s, "/path1/jwf944/path2/89qf23//")
			}},
		}
		reg, err := regexp.Compile(`^/path1/\w+/path2/\w+/{0,1}$`)
		assert.Nil(err)
		for _, aTest := range cases {
			aTest.testFunc(reg.Find([]byte(aTest.input)))
		}
	}

	// Case 4: path parameter at start of path
	{
		cases := []testCase{
			{input: "/q48ma8/path", testFunc: func(s []byte) {
				assert.NotNilf(s, "/q48ma8/path")
			}},
			{input: "/path", testFunc: func(s []byte) {
				assert.Nilf(s, "/path")
			}},
			{input: "/path/path/", testFunc: func(s []byte) {
				assert.NotNilf(s, "/path/path/")
			}},
		}
		reg, err := regexp.Compile(`^/\w+/path/{0,1}$`)
		assert.Nil(err)
		for _, aTest := range cases {
			aTest.testFunc(reg.Find([]byte(aTest.input)))
		}
	}

	// Case 5: path parameter support UUID or alphanumeric + "."
	{
		cases := []testCase{
			{input: "/path/2b44aafc-544e-45a0-bfd5-9018cae4849d", testFunc: func(s []byte) {
				assert.NotNilf(s, "/path/2b44aafc-544e-45a0-bfd5-9018cae4849d")
			}},
			{input: "/path/this.is.valid", testFunc: func(s []byte) {
				assert.NotNilf(s, "/path/this.is.valid")
			}},
			{input: "/path/this-is.not.valid", testFunc: func(s []byte) {
				assert.Nilf(s, "/path/this-is.not.valid")
			}},
			{input: "/path/this.is,not.valid", testFunc: func(s []byte) {
				assert.Nilf(s, "/path/this.is,not.valid")
			}},
			{input: "/path/not.valid.2b44aafc-544e-45a0-bfd5-9018cae4849d", testFunc: func(s []byte) {
				assert.Nilf(s, "/path/not.valid.2b44aafc-544e-45a0-bfd5-9018cae4849d")
			}},
		}
		reg, err := regexp.Compile(
			`^/path/([\w\.]+|[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12})/{0,1}$`,
		)
		assert.Nil(err)
		for _, aTest := range cases {
			aTest.testFunc(reg.Find([]byte(aTest.input)))
		}
	}
}
