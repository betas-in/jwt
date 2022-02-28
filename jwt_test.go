package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/betas-in/utils"
)

func TestAuth(t *testing.T) {
	token := NewToken("secret", 24*time.Hour, 30*24*time.Hour)
	at, rt, err := token.Generate(Payload{
		ID:    "12345",
		Email: "test@test.com",
	})
	utils.Test().Nil(t, err)
	utils.Test().Equals(t, 3, len(strings.Split(at, ".")))
	utils.Test().Equals(t, 3, len(strings.Split(rt, ".")))

	att, err := token.Validate(at)
	utils.Test().Nil(t, err)
	utils.Test().Equals(t, "12345", att.ID)
	utils.Test().Equals(t, "test@test.com", att.Email)
	utils.Test().Equals(t, true, att.Expiry > 0)

	rtt, err := token.Validate(rt)
	utils.Test().Nil(t, err)
	utils.Test().Equals(t, "12345", rtt.ID)
	utils.Test().Equals(t, "", rtt.Email)
	utils.Test().Equals(t, true, rtt.Expiry > 0)
}
