package authenticate

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestIntrospectResponseParse(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	// Case 0: test introspect response with `aud` as one string
	{
		audValue := uuid.NewString()
		testResponse := fmt.Sprintf("{\"aud\": \"%s\"}", audValue)
		var parsedResponse introspectResponse
		assert.Nil(json.Unmarshal([]byte(testResponse), &parsedResponse))
		assert.Len(parsedResponse.Audience, 1)
		assert.Equal(audValue, parsedResponse.Audience[0])
	}

	// Case 1: test introspect response with `aud` as a string array
	{
		audList := []string{uuid.NewString(), uuid.NewString()}
		testResponse := fmt.Sprintf("{\"aud\": [\"%s\", \"%s\"]}", audList[0], audList[1])
		var parsedResponse introspectResponse
		assert.Nil(json.Unmarshal([]byte(testResponse), &parsedResponse))
		assert.Len(parsedResponse.Audience, 2)
		assert.EqualValues(audList, parsedResponse.Audience)
	}
}

func TestIntrospector(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	cache := DefineTokenCache(time.Minute * 5)

	var tokenIsValid bool
	tokenIsValid = false

	dummyIntrospect := func(context.Context, string) (bool, error) {
		return tokenIsValid, nil
	}

	ctxt := context.Background()

	uut := DefineIntrospector(cache, dummyIntrospect)

	currentTime := time.Now().UTC()

	// Case 0: test token
	token1 := uuid.New().String()
	tokenExpire1 := currentTime.Add(time.Minute)
	tokenIsValid = true
	{
		valid, err := uut.VerifyToken(ctxt, token1, tokenExpire1.Unix(), currentTime)
		assert.Nil(err)
		assert.True(valid)
	}

	// Case 1: check token again
	{
		valid, err := uut.VerifyToken(ctxt, token1, tokenExpire1.Unix(), currentTime)
		assert.Nil(err)
		assert.True(valid)
	}

	// Case 2: token expired
	currentTime = currentTime.Add(time.Second * 90)
	tokenIsValid = false
	{
		valid, err := uut.VerifyToken(ctxt, token1, tokenExpire1.Unix(), currentTime)
		assert.Nil(err)
		assert.False(valid)
	}

	// Case 3: test token
	token2 := uuid.New().String()
	tokenExpire2 := currentTime.Add(time.Minute * 60)
	tokenIsValid = true
	{
		valid, err := uut.VerifyToken(ctxt, token2, tokenExpire2.Unix(), currentTime)
		assert.Nil(err)
		assert.True(valid)
	}

	// Case 4: enough time has passed, and must be re-introspected
	currentTime = currentTime.Add(time.Minute * 6)
	tokenIsValid = true
	{
		valid, err := uut.VerifyToken(ctxt, token2, tokenExpire2.Unix(), currentTime)
		assert.Nil(err)
		assert.True(valid)
	}

	// Case 5: more time passed, and the token is no longer valid
	currentTime = currentTime.Add(time.Minute * 5)
	tokenIsValid = false
	{
		valid, err := uut.VerifyToken(ctxt, token2, tokenExpire2.Unix(), currentTime)
		assert.Nil(err)
		assert.False(valid)
	}
}
