package authenticate

import (
	"context"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestTokenCache(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	uut := DefineTokenCache(time.Minute * 5)

	startTime := time.Now().UTC()

	ctxt := context.Background()

	// Case 0: empty cache
	{
		valid, err := uut.ValidTokenInCache(ctxt, uuid.New().String(), startTime)
		assert.Nil(err)
		assert.False(valid)
	}

	// Case 1: record a token
	token1 := uuid.New().String()
	currentTime := startTime
	tokenExpire1 := currentTime.Add(time.Minute)
	assert.Nil(uut.RecordToken(ctxt, token1, tokenExpire1.Unix(), currentTime))
	{
		valid, err := uut.ValidTokenInCache(ctxt, token1, currentTime)
		assert.Nil(err)
		assert.True(valid)
	}

	// Case 2: move time forward, token 1 expired
	currentTime = currentTime.Add(time.Minute * 2)
	{
		valid, err := uut.ValidTokenInCache(ctxt, token1, currentTime)
		assert.Nil(err)
		assert.False(valid)
	}

	// Case 3: record a token
	token2 := uuid.New().String()
	tokenExpire2 := currentTime.Add(time.Minute * 6)
	assert.Nil(uut.RecordToken(ctxt, token2, tokenExpire2.Unix(), currentTime))
	{
		valid, err := uut.ValidTokenInCache(ctxt, token2, currentTime)
		assert.Nil(err)
		assert.True(valid)
	}

	// Case 4: move time forward, token 2 need to be refreshed
	currentTime = currentTime.Add(time.Second * 330)
	{
		valid, err := uut.ValidTokenInCache(ctxt, token2, currentTime)
		assert.Nil(err)
		assert.False(valid)
	}

	// Case 4: record multiple tokens
	token3 := uuid.New().String()
	tokenExpire3 := currentTime.Add(time.Minute * 2)
	token4 := uuid.New().String()
	tokenExpire4 := currentTime.Add(time.Minute * 3)
	assert.Nil(uut.RecordToken(ctxt, token3, tokenExpire3.Unix(), currentTime))
	assert.Nil(uut.RecordToken(ctxt, token4, tokenExpire4.Unix(), currentTime))
	// Move time forward and clear out expired tokens
	currentTime = currentTime.Add(time.Second * 150)
	assert.Nil(uut.RemoveExpiredFromCache(ctxt, currentTime))
	currentTime = currentTime.Add(time.Second * 10)
	{
		valid, err := uut.ValidTokenInCache(ctxt, token3, currentTime)
		assert.Nil(err)
		assert.False(valid)
	}
	{
		valid, err := uut.ValidTokenInCache(ctxt, token4, currentTime)
		assert.Nil(err)
		assert.True(valid)
	}
}
