package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

// #TODO evaluate auth

// Token definition
type Token struct {
	Secret             string
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
}

// Payload definition
type Payload struct {
	ID     string
	Email  string
	Expiry int64
	Valid  bool
}

// NewToken generates a new token object
func NewToken(secret string, accessTokenExpiry, refreshTokenExpiry time.Duration) *Token {
	return &Token{
		Secret:             secret,
		AccessTokenExpiry:  accessTokenExpiry,
		RefreshTokenExpiry: refreshTokenExpiry,
	}
}

// HashPassword before saving to DB
func (t *Token) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	return string(hash), err
}

// CompareHashPassword definition
func (t *Token) CompareHashPassword(password, hashedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// Generate definition
func (t *Token) Generate(payload Payload) (string, string, error) {
	// Create token
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = payload.ID
	claims["email"] = payload.Email
	claims["exp"] = time.Now().Add(t.AccessTokenExpiry).Unix()

	// Generate access token
	accessToken, err := token.SignedString([]byte(t.Secret))
	if err != nil {
		return accessToken, "", err
	}

	// Create token
	token = jwt.New(jwt.SigningMethodHS256)
	claims = token.Claims.(jwt.MapClaims)
	claims["id"] = payload.ID
	claims["exp"] = time.Now().Add(t.RefreshTokenExpiry).Unix()

	// Generate refresh token
	refreshToken, err := token.SignedString([]byte(t.Secret))
	return accessToken, refreshToken, err
}

// Validate definition
func (t *Token) Validate(token string) (*Payload, error) {
	p := Payload{
		Valid: false,
	}

	parsed, err := jwt.Parse(token, func(jt *jwt.Token) (interface{}, error) {
		if _, ok := jt.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", jt.Header["alg"])
		}
		return []byte(t.Secret), nil
	})

	if claims, ok := parsed.Claims.(jwt.MapClaims); ok && parsed.Valid {
		id, ok := claims["id"].(string)
		if ok {
			p.ID = id
		}

		email, ok := claims["email"].(string)
		if ok {
			p.Email = email
		}

		expiry, ok := claims["exp"].(float64)
		if ok {
			p.Expiry = int64(expiry)
			p.Valid = (p.Expiry - time.Now().Unix()) >= 0
		}

		return &p, nil
	}
	return &p, err
}

// GetCookies definition
func (t *Token) GetCookies(accessToken, refreshToken string) []http.Cookie {
	// TODO : Add access token cookie domain
	return []http.Cookie{
		{
			Name:     "access_token",
			Value:    accessToken,
			Expires:  time.Now().Add(t.AccessTokenExpiry),
			Domain:   "",
			HttpOnly: true,
		},
		{
			Name:     "refresh_token",
			Value:    refreshToken,
			Expires:  time.Now().Add(t.RefreshTokenExpiry),
			Domain:   "",
			HttpOnly: true,
		},
	}
}
