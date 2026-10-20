// Copyright (c) 2026 Proton AG
//
// This file is part of Proton Mail Bridge.
//
// Proton Mail Bridge is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Proton Mail Bridge is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Proton Mail Bridge.  If not, see <https://www.gnu.org/licenses/>.

package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionLifetime   = 12 * time.Hour
	minPasswordLength = 8
	maxPasswordLength = 72 // bcrypt ignores everything after 72 bytes.
	failedLoginDelay  = time.Second
)

var (
	errWrongSetupToken     = errors.New("the setup token is incorrect")
	errAlreadySetUp        = errors.New("the web interface password is already set")
	errWrongPassword       = errors.New("the password is incorrect")
	errPasswordTooShort    = errors.New("the password must be at least 8 characters long")
	errPasswordTooLong     = errors.New("the password must be at most 72 bytes long")
	errSessionUnauthorized = errors.New("not signed in")
)

// passwordStore persists the bcrypt hash of the web interface password.
type passwordStore interface {
	GetWebPasswordHash() []byte
	SetWebPasswordHash(hash []byte) error
}

type session struct {
	csrfToken string
	expires   time.Time
}

// authenticator guards the web interface with a single admin password.
// Until the password is set, a one-time setup token is required to set it,
// so that nobody who merely reaches the port can claim the interface first.
type authenticator struct {
	store passwordStore

	lock       sync.Mutex
	setupToken string
	sessions   map[string]session

	// failLock serializes failed password checks so that each one costs failedLoginDelay.
	failLock sync.Mutex
}

func newAuthenticator(store passwordStore) *authenticator {
	auth := &authenticator{
		store:    store,
		sessions: make(map[string]session),
	}

	if auth.needsSetup() {
		auth.setupToken = randomToken()
	}

	return auth
}

func (auth *authenticator) needsSetup() bool {
	return len(auth.store.GetWebPasswordHash()) == 0
}

// getSetupToken returns the one-time token needed to set the password, or "" when the password is already set.
func (auth *authenticator) getSetupToken() string {
	auth.lock.Lock()
	defer auth.lock.Unlock()

	return auth.setupToken
}

// setup sets the first password and returns a new session token.
func (auth *authenticator) setup(token, password string) (string, error) {
	auth.lock.Lock()
	defer auth.lock.Unlock()

	if !auth.needsSetup() {
		return "", errAlreadySetUp
	}

	if subtle.ConstantTimeCompare([]byte(token), []byte(auth.setupToken)) != 1 {
		auth.delayFailure()
		return "", errWrongSetupToken
	}

	if err := auth.storePassword(password); err != nil {
		return "", err
	}

	auth.setupToken = ""

	return auth.newSessionLocked(), nil
}

// login checks the password and returns a new session token.
func (auth *authenticator) login(password string) (string, error) {
	if bcrypt.CompareHashAndPassword(auth.store.GetWebPasswordHash(), []byte(password)) != nil {
		auth.delayFailure()
		return "", errWrongPassword
	}

	auth.lock.Lock()
	defer auth.lock.Unlock()

	return auth.newSessionLocked(), nil
}

// changePassword replaces the password and signs out every session except the given one.
func (auth *authenticator) changePassword(sessionToken, current, password string) error {
	if bcrypt.CompareHashAndPassword(auth.store.GetWebPasswordHash(), []byte(current)) != nil {
		auth.delayFailure()
		return errWrongPassword
	}

	auth.lock.Lock()
	defer auth.lock.Unlock()

	if err := auth.storePassword(password); err != nil {
		return err
	}

	for token := range auth.sessions {
		if token != sessionToken {
			delete(auth.sessions, token)
		}
	}

	return nil
}

// getSession returns the session for the given token if it exists and has not expired.
func (auth *authenticator) getSession(token string) (session, bool) {
	auth.lock.Lock()
	defer auth.lock.Unlock()

	sess, ok := auth.sessions[token]
	if !ok {
		return session{}, false
	}

	if time.Now().After(sess.expires) {
		delete(auth.sessions, token)
		return session{}, false
	}

	return sess, true
}

func (auth *authenticator) logout(token string) {
	auth.lock.Lock()
	defer auth.lock.Unlock()

	delete(auth.sessions, token)
}

func (auth *authenticator) storePassword(password string) error {
	if len(password) < minPasswordLength {
		return errPasswordTooShort
	}

	if len(password) > maxPasswordLength {
		return errPasswordTooLong
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return auth.store.SetWebPasswordHash(hash)
}

func (auth *authenticator) newSessionLocked() string {
	token := randomToken()

	auth.sessions[token] = session{
		csrfToken: randomToken(),
		expires:   time.Now().Add(sessionLifetime),
	}

	return token
}

func (auth *authenticator) delayFailure() {
	auth.failLock.Lock()
	defer auth.failLock.Unlock()

	time.Sleep(failedLoginDelay)
}

func randomToken() string {
	b := make([]byte, 32)

	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return hex.EncodeToString(b)
}
