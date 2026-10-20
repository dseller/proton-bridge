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
	"context"
	"errors"
	"sync"

	"github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/proton-bridge/v3/internal/bridge"
	"github.com/ProtonMail/proton-bridge/v3/internal/hv"
)

const maxMailboxPasswordAttempts = 3

const (
	stepTOTP    = "totp"
	stepMailbox = "mailbox"
	stepHV      = "hv"
	stepDone    = "done"
)

// loginStep tells the web page what the account sign-in needs next.
type loginStep struct {
	Step  string `json:"step"`
	HVURL string `json:"hv_url,omitempty"`
	Error string `json:"error,omitempty"`
}

// accountLogin holds one account sign-in in progress.
// The sign-in goes through password, optional human verification, optional TOTP and optional mailbox password.
type accountLogin struct {
	lock sync.Mutex

	username string
	password []byte

	client *proton.Client
	auth   proton.Auth

	hvDetails *proton.APIHVDetails
	useHV     bool

	mailboxAttempts int
}

func (s *Server) getAccountLogin(sessionToken string) (*accountLogin, bool) {
	s.loginsLock.Lock()
	defer s.loginsLock.Unlock()

	login, ok := s.logins[sessionToken]

	return login, ok
}

func (s *Server) dropAccountLogin(sessionToken string) {
	s.loginsLock.Lock()
	defer s.loginsLock.Unlock()

	if login, ok := s.logins[sessionToken]; ok {
		clear(login.password)
		delete(s.logins, sessionToken)
	}
}

// startAccountLogin begins a new sign-in for the given session, replacing any sign-in already in progress.
func (s *Server) startAccountLogin(sessionToken, username, password string) loginStep {
	s.dropAccountLogin(sessionToken)

	login := &accountLogin{
		username: username,
		password: []byte(password),
	}

	s.loginsLock.Lock()
	s.logins[sessionToken] = login
	s.loginsLock.Unlock()

	login.lock.Lock()
	defer login.lock.Unlock()

	return s.finishStep(sessionToken, s.authorize(login))
}

// continueAfterHV repeats the authorization with the human verification token once the user has solved the challenge.
func (s *Server) continueAfterHV(sessionToken string) loginStep {
	login, ok := s.getAccountLogin(sessionToken)
	if !ok {
		return loginStep{Error: "No sign-in is in progress."}
	}

	login.lock.Lock()
	defer login.lock.Unlock()

	if login.hvDetails == nil {
		return s.finishStep(sessionToken, loginStep{Error: hv.VerificationFailedErrorMsg})
	}

	login.useHV = true

	return s.finishStep(sessionToken, s.authorize(login))
}

func (s *Server) submitTOTP(sessionToken, code string) loginStep {
	login, ok := s.getAccountLogin(sessionToken)
	if !ok {
		return loginStep{Error: "No sign-in is in progress."}
	}

	login.lock.Lock()
	defer login.lock.Unlock()

	if login.client == nil {
		return s.finishStep(sessionToken, loginStep{Error: "Missing authentication, try again."})
	}

	if err := login.client.Auth2FA(context.Background(), proton.Auth2FAReq{TwoFactorCode: code}); err != nil {
		if apiErr := new(proton.APIError); errors.As(err, &apiErr) && apiErr.Code == proton.PasswordWrong {
			return loginStep{Step: stepTOTP, Error: "The two-factor code is incorrect."}
		}

		return s.finishStep(sessionToken, loginStep{Error: err.Error()})
	}

	return s.finishStep(sessionToken, s.afterTwoFactor(login))
}

func (s *Server) submitMailboxPassword(sessionToken, password string) loginStep {
	login, ok := s.getAccountLogin(sessionToken)
	if !ok {
		return loginStep{Error: "No sign-in is in progress."}
	}

	login.lock.Lock()
	defer login.lock.Unlock()

	if login.client == nil {
		return s.finishStep(sessionToken, loginStep{Error: "Missing authentication, try again."})
	}

	return s.finishStep(sessionToken, s.unlock(login, []byte(password)))
}

// finishStep drops the sign-in when the step ends it, either because it failed or because it is done.
func (s *Server) finishStep(sessionToken string, step loginStep) loginStep {
	if step.Step == "" || step.Step == stepDone {
		s.dropAccountLogin(sessionToken)
	}

	return step
}

func (s *Server) authorize(login *accountLogin) loginStep {
	var hvDetails *proton.APIHVDetails
	if login.useHV {
		hvDetails = login.hvDetails
	}

	client, auth, err := s.bridge.LoginAuth(context.Background(), login.username, login.password, hvDetails)
	if err != nil {
		return s.authorizeError(login, err)
	}

	login.client = client
	login.auth = auth

	switch auth.TwoFA.Enabled {
	case proton.HasTOTP, proton.HasFIDO2AndTOTP:
		return loginStep{Step: stepTOTP}

	case proton.HasFIDO2:
		return loginStep{Error: "This account requires a security key, which the web interface does not support. Add an authenticator app to the account to sign in here."}
	}

	return s.afterTwoFactor(login)
}

func (s *Server) authorizeError(login *accountLogin, err error) loginStep {
	if errors.Is(err, bridge.ErrUserAlreadyLoggedIn) {
		return loginStep{Error: "This account is already signed in."}
	}

	if step, ok := s.humanVerificationStep(login, err); ok {
		return step
	}

	if apiErr := new(proton.APIError); errors.As(err, &apiErr) {
		switch apiErr.Code { //nolint:exhaustive
		case proton.PasswordWrong, proton.UsernameInvalid:
			return loginStep{Error: "The username or password is incorrect."}

		case proton.PaidPlanRequired:
			return loginStep{Error: "Bridge requires a paid Proton Mail plan."}

		case proton.HumanValidationInvalidToken:
			return loginStep{Error: hv.VerificationFailedErrorMsg}
		}
	}

	return loginStep{Error: err.Error()}
}

func (s *Server) afterTwoFactor(login *accountLogin) loginStep {
	if login.auth.PasswordMode == proton.TwoPasswordMode {
		return loginStep{Step: stepMailbox}
	}

	return s.unlock(login, login.password)
}

// unlock finishes the sign-in by unlocking the account keys with the given key password.
func (s *Server) unlock(login *accountLogin, keyPass []byte) loginStep {
	var hvDetails *proton.APIHVDetails
	if login.useHV {
		hvDetails = login.hvDetails
	}

	if _, err := s.bridge.LoginUser(context.Background(), login.client, login.auth, keyPass, hvDetails); err != nil {
		if step, ok := s.humanVerificationStep(login, err); ok {
			return step
		}

		if apiErr := new(proton.APIError); errors.As(err, &apiErr) && apiErr.Code == proton.HumanValidationInvalidToken {
			return loginStep{Error: hv.VerificationFailedErrorMsg}
		}

		if errors.Is(err, bridge.ErrFailedToUnlock) && login.auth.PasswordMode == proton.TwoPasswordMode {
			login.mailboxAttempts++

			if login.mailboxAttempts < maxMailboxPasswordAttempts {
				return loginStep{Step: stepMailbox, Error: "The mailbox password is incorrect."}
			}

			if deleteErr := login.client.AuthDelete(context.Background()); deleteErr != nil {
				s.log.WithError(deleteErr).Error("Failed to delete auth")
			}
		}

		return loginStep{Error: err.Error()}
	}

	return loginStep{Step: stepDone}
}

// humanVerificationStep returns the human verification step if the error asks for one.
func (s *Server) humanVerificationStep(login *accountLogin, err error) (loginStep, bool) {
	if !hv.IsHvRequest(err) {
		return loginStep{}, false
	}

	hvDetails, hvErr := hv.VerifyAndExtractHvRequest(err)
	if hvErr != nil || hvDetails == nil {
		s.bridge.ReportMessageWithContext("Unable to extract HV request details", map[string]any{
			"error": err.Error(),
		})

		return loginStep{Error: hv.ExtractionErrorMsg}, true
	}

	login.hvDetails = hvDetails
	login.client = nil
	login.auth = proton.Auth{}

	return loginStep{Step: stepHV, HVURL: hv.FormatHvURL(hvDetails)}, true
}
