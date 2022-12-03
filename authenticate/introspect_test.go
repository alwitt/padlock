package authenticate

import (
	"context"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

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
