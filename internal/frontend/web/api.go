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
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/ProtonMail/gluon/async"
	"github.com/ProtonMail/proton-bridge/v3/internal/bridge"
	"github.com/ProtonMail/proton-bridge/v3/internal/constants"
	"github.com/ProtonMail/proton-bridge/v3/internal/events"
	"github.com/ProtonMail/proton-bridge/v3/internal/updater"
	"github.com/ProtonMail/proton-bridge/v3/internal/vault"
	"github.com/ProtonMail/proton-bridge/v3/pkg/ports"
)

const (
	sessionCookieName = "bridge_session"
	csrfHeaderName    = "X-CSRF-Token"
	maxRequestBytes   = 64 * 1024
)

type sessionHandler func(w http.ResponseWriter, r *http.Request, sessionToken string)

// withSession rejects requests without a valid session, and state-changing requests without the session's CSRF token.
func (s *Server) withSession(next sessionHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			writeError(w, http.StatusUnauthorized, errSessionUnauthorized.Error())
			return
		}

		sess, ok := s.auth.getSession(cookie.Value)
		if !ok {
			writeError(w, http.StatusUnauthorized, errSessionUnauthorized.Error())
			return
		}

		if r.Method != http.MethodGet && subtle.ConstantTimeCompare([]byte(r.Header.Get(csrfHeaderName)), []byte(sess.csrfToken)) != 1 {
			writeError(w, http.StatusForbidden, "missing or invalid CSRF token")
			return
		}

		next(w, r, cookie.Value)
	}
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionLifetime.Seconds()),
		HttpOnly: true,
		Secure:   s.useTLS,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.useTLS,
		SameSite: http.SameSiteStrictMode,
	})
}

type sessionResponse struct {
	SetupRequired bool   `json:"setup_required"`
	SignedIn      bool   `json:"signed_in"`
	CSRFToken     string `json:"csrf_token,omitempty"`
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	res := sessionResponse{SetupRequired: s.auth.needsSetup()}

	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if sess, ok := s.auth.getSession(cookie.Value); ok {
			res.SignedIn = true
			res.CSRFToken = sess.csrfToken
		}
	}

	writeJSON(w, res)
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}

	if !readJSON(w, r, &req) {
		return
	}

	token, err := s.auth.setup(req.Token, req.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.log.Info("Web interface password set")
	s.setSessionCookie(w, token)
	writeJSON(w, struct{}{})
}

func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}

	if !readJSON(w, r, &req) {
		return
	}

	token, err := s.auth.login(req.Password)
	if err != nil {
		s.log.WithField("remote", r.RemoteAddr).Warn("Failed sign-in to the web interface")
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	s.setSessionCookie(w, token)
	writeJSON(w, struct{}{})
}

func (s *Server) handleSignOut(w http.ResponseWriter, _ *http.Request, sessionToken string) {
	s.dropAccountLogin(sessionToken)
	s.auth.logout(sessionToken)
	s.clearSessionCookie(w)
	writeJSON(w, struct{}{})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, sessionToken string) {
	var req struct {
		Current  string `json:"current"`
		Password string `json:"password"`
	}

	if !readJSON(w, r, &req) {
		return
	}

	if err := s.auth.changePassword(sessionToken, req.Current, req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.log.Info("Web interface password changed")
	writeJSON(w, struct{}{})
}

type accountResponse struct {
	ID             string      `json:"id"`
	Username       string      `json:"username"`
	State          string      `json:"state"`
	Addresses      []string    `json:"addresses"`
	Split          bool        `json:"split"`
	BridgePassword string      `json:"bridge_password"`
	UsedSpace      uint64      `json:"used_space"`
	MaxSpace       uint64      `json:"max_space"`
	Sync           *syncStatus `json:"sync"`
	BadEvent       string      `json:"bad_event,omitempty"`
}

type settingsResponse struct {
	Host              string `json:"host"`
	IMAPPort          int    `json:"imap_port"`
	SMTPPort          int    `json:"smtp_port"`
	IMAPSSL           bool   `json:"imap_ssl"`
	SMTPSSL           bool   `json:"smtp_ssl"`
	CacheDir          string `json:"cache_dir"`
	ShowAllMail       bool   `json:"show_all_mail"`
	ProxyAllowed      bool   `json:"proxy_allowed"`
	TelemetryDisabled bool   `json:"telemetry_disabled"`
	AutoUpdate        bool   `json:"auto_update"`
	EarlyAccess       bool   `json:"early_access"`
}

type updateResponse struct {
	AvailableVersion string `json:"available_version,omitempty"`
	RestartNeeded    bool   `json:"restart_needed"`
}

type statusResponse struct {
	Version   string            `json:"version"`
	Connected bool              `json:"connected"`
	Accounts  []accountResponse `json:"accounts"`
	Settings  settingsResponse  `json:"settings"`
	Update    updateResponse    `json:"update"`
	Notices   []notice          `json:"notices"`
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request, _ string) {
	res := statusResponse{
		Version:   s.bridge.GetCurrentVersion().String(),
		Connected: s.bridge.HasAPIConnection(),
		Accounts:  []accountResponse{},
		Settings: settingsResponse{
			Host:              constants.Host,
			IMAPPort:          s.bridge.GetIMAPPort(),
			SMTPPort:          s.bridge.GetSMTPPort(),
			IMAPSSL:           s.bridge.GetIMAPSSL(),
			SMTPSSL:           s.bridge.GetSMTPSSL(),
			CacheDir:          s.bridge.GetGluonCacheDir(),
			ShowAllMail:       s.bridge.GetShowAllMail(),
			ProxyAllowed:      s.bridge.GetProxyAllowed(),
			TelemetryDisabled: s.bridge.GetTelemetryDisabled(),
			AutoUpdate:        s.bridge.GetAutoUpdate(),
			EarlyAccess:       s.bridge.GetUpdateChannel() == updater.EarlyChannel,
		},
		Update: updateResponse{
			RestartNeeded: s.state.isRestartNeeded(),
		},
		Notices: s.state.getNotices(),
	}

	if target := s.state.getUpdateTarget(); !target.IsEmpty() && target.Version != nil {
		res.Update.AvailableVersion = target.Version.String()
	}

	for _, userID := range s.bridge.GetUserIDs() {
		user, err := s.bridge.GetUserInfo(userID)
		if err != nil {
			continue
		}

		account := accountResponse{
			ID:        user.UserID,
			Username:  user.Username,
			State:     userStateName(user.State),
			Addresses: user.Addresses,
			Split:     user.AddressMode == vault.SplitMode,
			UsedSpace: user.UsedSpace,
			MaxSpace:  user.MaxSpace,
			BadEvent:  s.state.getBadEvent(user.UserID),
		}

		if user.State == bridge.Connected {
			account.BridgePassword = string(user.BridgePass)
		}

		if sync, ok := s.state.getSync(user.UserID); ok {
			account.Sync = &sync
		}

		res.Accounts = append(res.Accounts, account)
	}

	writeJSON(w, res)
}

func userStateName(state bridge.UserState) string {
	switch state {
	case bridge.SignedOut:
		return "signed_out"
	case bridge.Locked:
		return "locked"
	case bridge.Connected:
		return "connected"
	default:
		return "unknown"
	}
}

// settingsRequest holds the settings to change; settings left out are not changed.
type settingsRequest struct {
	IMAPPort          *int    `json:"imap_port"`
	SMTPPort          *int    `json:"smtp_port"`
	IMAPSSL           *bool   `json:"imap_ssl"`
	SMTPSSL           *bool   `json:"smtp_ssl"`
	CacheDir          *string `json:"cache_dir"`
	ShowAllMail       *bool   `json:"show_all_mail"`
	ProxyAllowed      *bool   `json:"proxy_allowed"`
	TelemetryDisabled *bool   `json:"telemetry_disabled"`
	AutoUpdate        *bool   `json:"auto_update"`
	EarlyAccess       *bool   `json:"early_access"`
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request, _ string) {
	var req settingsRequest

	if !readJSON(w, r, &req) {
		return
	}

	if err := s.applySettings(context.Background(), req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, struct{}{})
}

func (s *Server) applySettings(ctx context.Context, req settingsRequest) error { //nolint:gocyclo
	if req.IMAPPort != nil && *req.IMAPPort != s.bridge.GetIMAPPort() {
		if !ports.IsPortFree(*req.IMAPPort) {
			return fmt.Errorf("IMAP port %d is invalid or already in use", *req.IMAPPort)
		}

		if err := s.bridge.SetIMAPPort(ctx, *req.IMAPPort); err != nil {
			return fmt.Errorf("could not change the IMAP port: %w", err)
		}
	}

	if req.SMTPPort != nil && *req.SMTPPort != s.bridge.GetSMTPPort() {
		if !ports.IsPortFree(*req.SMTPPort) {
			return fmt.Errorf("SMTP port %d is invalid or already in use", *req.SMTPPort)
		}

		if err := s.bridge.SetSMTPPort(ctx, *req.SMTPPort); err != nil {
			return fmt.Errorf("could not change the SMTP port: %w", err)
		}
	}

	if req.IMAPSSL != nil && *req.IMAPSSL != s.bridge.GetIMAPSSL() {
		if err := s.bridge.SetIMAPSSL(ctx, *req.IMAPSSL); err != nil {
			return fmt.Errorf("could not change the IMAP security: %w", err)
		}
	}

	if req.SMTPSSL != nil && *req.SMTPSSL != s.bridge.GetSMTPSSL() {
		if err := s.bridge.SetSMTPSSL(ctx, *req.SMTPSSL); err != nil {
			return fmt.Errorf("could not change the SMTP security: %w", err)
		}
	}

	if req.CacheDir != nil && *req.CacheDir != s.bridge.GetGluonCacheDir() {
		if stat, err := os.Stat(*req.CacheDir); err != nil || !stat.IsDir() {
			return fmt.Errorf("the cache location %q is not an existing directory", *req.CacheDir)
		}

		if err := s.bridge.SetGluonDir(ctx, *req.CacheDir); err != nil {
			return fmt.Errorf("could not move the message cache: %w", err)
		}
	}

	if req.ShowAllMail != nil {
		if err := s.bridge.SetShowAllMail(*req.ShowAllMail); err != nil {
			return fmt.Errorf("could not change whether All Mail is shown: %w", err)
		}
	}

	if req.ProxyAllowed != nil {
		if err := s.bridge.SetProxyAllowed(*req.ProxyAllowed); err != nil {
			return fmt.Errorf("could not change alternative routing: %w", err)
		}
	}

	if req.TelemetryDisabled != nil {
		if err := s.bridge.SetTelemetryDisabled(*req.TelemetryDisabled); err != nil {
			return fmt.Errorf("could not change usage diagnostics collection: %w", err)
		}
	}

	if req.AutoUpdate != nil {
		if err := s.bridge.SetAutoUpdate(*req.AutoUpdate); err != nil {
			return fmt.Errorf("could not change automatic updates: %w", err)
		}
	}

	if req.EarlyAccess != nil {
		channel := updater.StableChannel
		if *req.EarlyAccess {
			channel = updater.EarlyChannel
		}

		if channel != s.bridge.GetUpdateChannel() {
			if err := s.bridge.SetUpdateChannel(channel); err != nil {
				return fmt.Errorf("could not change the update channel: %w", err)
			}
		}
	}

	return nil
}

func (s *Server) handleDismissNotice(w http.ResponseWriter, r *http.Request, _ string) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid notice ID")
		return
	}

	s.state.dismissNotice(id)
	writeJSON(w, struct{}{})
}

func (s *Server) handleCheckUpdates(w http.ResponseWriter, _ *http.Request, _ string) {
	go func() {
		defer async.HandlePanic(s.panicHandler)

		updateCh, done := s.bridge.GetEvents(events.UpdateAvailable{}, events.UpdateNotAvailable{}, events.UpdateCheckFailed{})
		defer done()

		s.bridge.CheckForUpdates()

		switch event := (<-updateCh).(type) {
		case events.UpdateNotAvailable:
			s.state.addNotice(levelInfo, "Bridge is up to date.")

		case events.UpdateCheckFailed:
			s.state.addNotice(levelError, "Bridge could not check for updates: %v", event.Error)

		case events.UpdateAvailable:
			// The event watcher records the available update.
		}
	}()

	writeJSON(w, struct{}{})
}

func (s *Server) handleInstallUpdate(w http.ResponseWriter, _ *http.Request, _ string) {
	target := s.state.getUpdateTarget()
	if target.IsEmpty() {
		writeError(w, http.StatusBadRequest, "no update is available")
		return
	}

	go func() {
		defer async.HandlePanic(s.panicHandler)
		s.bridge.InstallUpdate(target)
	}()

	writeJSON(w, struct{}{})
}

func (s *Server) handleRestart(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSON(w, struct{}{})
	s.restart()
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Code     string `json:"code"`
}

func (s *Server) handleAccountLogin(w http.ResponseWriter, r *http.Request, sessionToken string) {
	var req loginRequest

	if !readJSON(w, r, &req) {
		return
	}

	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "the username and password are required")
		return
	}

	writeJSON(w, s.startAccountLogin(sessionToken, req.Username, req.Password))
}

func (s *Server) handleAccountLoginHV(w http.ResponseWriter, _ *http.Request, sessionToken string) {
	writeJSON(w, s.continueAfterHV(sessionToken))
}

func (s *Server) handleAccountLoginTOTP(w http.ResponseWriter, r *http.Request, sessionToken string) {
	var req loginRequest

	if !readJSON(w, r, &req) {
		return
	}

	writeJSON(w, s.submitTOTP(sessionToken, req.Code))
}

func (s *Server) handleAccountLoginMailbox(w http.ResponseWriter, r *http.Request, sessionToken string) {
	var req loginRequest

	if !readJSON(w, r, &req) {
		return
	}

	writeJSON(w, s.submitMailboxPassword(sessionToken, req.Password))
}

func (s *Server) handleAccountLoginAbort(w http.ResponseWriter, _ *http.Request, sessionToken string) {
	s.dropAccountLogin(sessionToken)
	writeJSON(w, struct{}{})
}

func (s *Server) handleAccountSignOut(w http.ResponseWriter, r *http.Request, _ string) {
	if err := s.bridge.LogoutUser(context.Background(), r.PathValue("id")); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, struct{}{})
}

func (s *Server) handleAccountRemove(w http.ResponseWriter, r *http.Request, _ string) {
	if err := s.bridge.DeleteUser(context.Background(), r.PathValue("id")); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, struct{}{})
}

func (s *Server) handleAccountMode(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		Split bool `json:"split"`
	}

	if !readJSON(w, r, &req) {
		return
	}

	mode := vault.CombinedMode
	if req.Split {
		mode = vault.SplitMode
	}

	if err := s.bridge.SetAddressMode(context.Background(), r.PathValue("id"), mode); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, struct{}{})
}

func (s *Server) handleAccountBadEvent(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		Resync bool `json:"resync"`
	}

	if !readJSON(w, r, &req) {
		return
	}

	userID := r.PathValue("id")

	if err := s.bridge.SendBadEventUserFeedback(context.Background(), userID, req.Resync); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.state.clearBadEvent(userID)
	writeJSON(w, struct{}{})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)

	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return false
	}

	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")

	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: message})
}
