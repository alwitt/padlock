package match

import (
	"fmt"
	"regexp"
)

// RegexCheck accepts a string
type RegexCheck interface {
	/*
		Match checks whether this regex finds a match against the input

		 @param s []byte - the string against
		 @return nil if a match is found
		         an error otherwise
	*/
	Match(s []byte) error
}

// regexCheckImpl implements RegexCheck
type regexCheckImpl struct {
	pattern string
	core    *regexp.Regexp
}

/*
Match checks whether this regex finds a match against the input

 @param s []byte - the string against
 @return nil if a match is found
         an error otherwise
*/
func (c *regexCheckImpl) Match(s []byte) error {
	if c.core.Find(s) == nil {
		return fmt.Errorf("'%s' =/= '%s'", s, c.pattern)
	}
	return nil
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
