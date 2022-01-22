package common

import (
	"bytes"
	"context"
	"encoding/gob"

	"github.com/apex/log"
)

// Component is the base structure for all components
type Component struct {
	// LogTags the Apex logging message metadata tags
	LogTags log.Fields
}

/*
GetLogTagsForContext creates a new Apex log.Fields metadata structure for a specific context

 @param ctxt context.Context - the unique context
 @return the new Apec log.Fields metadata
*/
func (c Component) GetLogTagsForContext(ctxt context.Context) log.Fields {
	// Make a deep copy of the starting logtags
	result := log.Fields{}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&c.LogTags); err != nil {
		return c.LogTags
	}
	if err := gob.NewDecoder(bytes.NewBuffer(buf.Bytes())).Decode(&result); err != nil {
		return c.LogTags
	}
	if ctxt.Value(RequestParam{}) != nil {
		v, ok := ctxt.Value(RequestParam{}).(RequestParam)
		if ok {
			v.updateLogTags(result)
		}
	}
	return result
}
