// Copyright 2015 Ayke van Laethem. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

// Package south provides stateless HTTP authentication using cookies.
//
// It works by saving the user ID and expirity information to a cookie, signed
// with HMAC-256. This cookie can later be verified.
// Note: this package only signs the cookie, it doesn't encrypt it. Therefore,
// the user ID, creation time (in seconds) and the expirity will be visible.
//
// The user ID must be able to fit in a cookie value and not contain a colon.
// This means simple identifiers (including numbers) are allowed, but also
// e-mail adresses as defined by the HTML5 spec:
// https://html.spec.whatwg.org/multipage/forms.html#valid-e-mail-address.
package south

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidId    = errors.New("south: user ID contains invalid characters")
	ErrInvalidToken = errors.New("south: invalid token")
	ErrExpiredToken = errors.New("south: token expired")
	ErrKeySize      = errors.New("south: key does not have the right size")
)

// KeySize is the minimum size of the HMAC-SHA256 key.
const KeySize = sha256.Size

// DefaultDuration is the default session duration for a session store.
const DefaultDuration = 7 * 86400 // seven days

const DefaultCookieName = "sessionToken"

// Store saves authentication tokens inside cookies.
type Store struct {
	// The time after which tokens will expire, defaulting to DefaultDuration.
	Duration int

	// CookieName is the cookie name returned by Token.Cookie(), defaulting to
	// DefaultCookieName.
	CookieName string

	// cookiePath is the path for the cookie returned by Token.Cookie().
	cookiePath string

	// HMAC key
	key []byte
}

// Token is a single authentication token for one user ID.
type Token struct {
	auth *Store
	id   string
}

// GenerateKey returns a new key of the right size for use by the session store.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// New returns a new session store.
// A new key can be generated using GenerateKey().
// Returns an error if the key does not have the right length.
func New(key []byte, path string) (*Store, error) {
	// The cookie path must not be left empty
	if len(key) != KeySize {
		return nil, ErrKeySize
	}

	return &Store{
		Duration: DefaultDuration,
		CookieName: DefaultCookieName,
		cookiePath: path,
		key: key,
	}, nil
}

// NewToken returns a new Token for this user ID. An error may be returned if
// the id doesn't adhere to the requirements (see package documentation for
// requirements on token IDs).
func (s *Store) NewToken(id string) (*Token, error) {
	if !validId(id) {
		return nil, ErrInvalidId
	}

	return &Token{s, id}, nil
}

// Cookie returns a new cookie that can be appended to a request. You may want
// to regenerate the cookie for each request, to keep the session alive.
//
// The returned cookie is secure by default: the 'secure' and 'httpOnly' flags
// are set. If you want to use this cookie over plain HTTP without SSL (making
// the token vulnerable to interception) or want to read it using JavaScript
// (making the token vulnerable to XSS attacks), you may modify the relevant
// flags inside the returned cookie.
func (t *Token) Cookie() *http.Cookie {
	created := time.Now().Unix()
	token := t.id + ":" + strconv.FormatInt(created, 10)

	mac := signMessage(token, t.auth.key)
	token += ":" + base64.URLEncoding.EncodeToString(mac)

	return &http.Cookie{Name: t.auth.CookieName, Value: token, Path: t.auth.cookiePath, MaxAge: t.auth.Duration, Secure: true, HttpOnly: true}
}

// Verify verifies the token encapsulated inside the HTTP cookie.
// The error returned can be ErrInvalidToken or ErrExpiredToken for invalid or
// expred tokens, respectively.
//
// ErrExpiredToken will not normally be returned, as cookie tokens should be
// removed by the browser once they expire.
func (s *Store) Verify(c *http.Cookie) (*Token, error) {
	fields := strings.Split(c.Value, ":")
	if len(fields) != 3 {
		return nil, ErrInvalidToken
	}

	mac1, err := base64.URLEncoding.DecodeString(fields[2])
	if err != nil {
		// Treat this error just like any other token decode error.
		return nil, ErrInvalidToken
	}

	mac2 := signMessage(strings.Join(fields[:2], ":"), s.key)

	if !hmac.Equal(mac1, mac2) {
		// It looks like either the token has been tampered with, or the key has
		// changed.
		return nil, ErrInvalidToken
	}

	// This is a valid token.
	// Now check whether it hasn't expired yet.

	created, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		// This may be an error on our side: the token has been verified but
		// contains invalid data...
		return nil, ErrInvalidToken
	}

	now := time.Now().Unix()

	if created+int64(s.Duration) < now {
		// This will not happen often in practice, as the cookie will have been
		// deleted by the browser already.
		return nil, ErrExpiredToken
	}

	return &Token{s, fields[0]}, nil
}

// Id returns the user ID for this token.
func (t *Token) Id() string {
	return t.id
}

// Rerturn true if this user ID string does not contain invalid characters.
func validId(id string) bool {
	for _, c := range id {
		// See http://tools.ietf.org/html/rfc6265#section-4.1.1 for the allowed
		// characters. Luckily, e-mail addresses exactly fit into this
		// definition.
		if c < '!' || c > '~' {
			// Not a printable US-ASCII character.
			return false
		}
		if c == ':' {
			// ':' is not allowed as we use it ourselves to separate fields.
			// Colons are not allowed in e-mail adresses as defined by the HTML5
			// spec.
			return false
		}
		switch c {
		case ' ', '"', ',', ';', '\\':
			// Not allowed in cookie values (see cookie-octet in the linked
			// RFC).
			return false
		}
	}

	return true
}

// A helper function for HMAC-SHA256. The key must be of the right length, or
// this function will panic.
func signMessage(message string, key []byte) []byte {
	if len(key) != KeySize {
		panic("HMAC key is not the right size")
	}

	signer := hmac.New(sha256.New, key)
	signer.Write([]byte(message))
	return signer.Sum(nil)
}
