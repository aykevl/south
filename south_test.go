// Copyright 2015 Ayke van Laethem. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package south

import (
	"bytes"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key1, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	key2, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(key1, key2) == 0 {
		t.Fatal("HMAC keys are equal!")
	}
}

func TestTokenStore(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	store, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	token, err := store.NewToken("test")
	if err != nil {
		t.Fatal(err)
	}

	cookie := token.Cookie()

	_, err = store.Verify(cookie)
	if err != nil {
		t.Fatal(err)
	}

	// Try corrupting the cookie.

	for i := range cookie.Value {
		v := []byte(cookie.Value)
		v[i] ^= 0x80
		cookie.Value = string(v)

		_, err := store.Verify(cookie)
		if err == nil {
			t.Errorf("token was verified after corrupting byte %d", i)
		}

		v[i] ^= 0x80
		cookie.Value = string(v)
	}

	// Test with a different key and store.

	key2, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	store2, err := New(key2)
	if err != nil {
		t.Fatal(err)
	}

	_, err = store2.Verify(cookie)
	if err == nil {
		t.Error("token was verified with a different key & store")
	}

	// Test with a different store but the original key.

	store3, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = store3.Verify(cookie)
	if err != nil {
		t.Error("token could not be verified in a different store")
	}

	store3.Duration = -1
	_, err = store3.Verify(cookie)
	if err != ErrExpiredToken {
		t.Error("token did not properly expire")
	}
}

func TestTokenId(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	store, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	// These ID forms must be valid.
	ids := []string{
		"Test",
		"a-x_y@b.c",
		"0123456789",
	}

	for _, id := range ids {
		token1, err := store.NewToken(id)
		if err != nil {
			t.Fatal(err)
		}

		token2, err := store.Verify(token1.Cookie())
		if err != nil {
			t.Fatal(err)
		}
		if token1.Id() != token2.Id() {
			t.Fatal("IDs don't match")
		}
	}
}
