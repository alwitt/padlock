package common

import (
	"fmt"
	"regexp"
)

// RegexCheck is a wrapper object to perform a regex check against a string
type RegexCheck interface {
	/*
		Match checks whether this regex finds a match against the input

		 @param s []byte - the string against
		 @return whether the input matchs against the regex
	*/
	Match(s []byte) (bool, error)

	/*
		String returns an ASCII description of the object

		 @return an ASCII description of the object
	*/
	String() string
}

// regexCheckImpl implements RegexCheck
type regexCheckImpl struct {
	pattern string
	core    *regexp.Regexp
}

/*
Match checks whether this regex finds a match against the input

 @param s []byte - the string against
 @return whether the input matchs against the regex
*/
func (c *regexCheckImpl) Match(s []byte) (bool, error) {
	if c.core.Find(s) == nil {
		return false, nil
	}
	return true, nil
}

/*
String returns an ASCII description of the object

 @return an ASCII description of the object
*/
func (c *regexCheckImpl) String() string {
	return fmt.Sprintf("REGEX['%s']", c.pattern)
}

/*
NewRegexCheck defines a new RegexCheck object

 @param pattern string - regex pattern
 @return the RegexCheck instance
*/
func NewRegexCheck(pattern string) (RegexCheck, error) {
	reg, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &regexCheckImpl{pattern: pattern, core: reg}, nil
}
