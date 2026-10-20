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
	"fmt"
	"sync"
	"time"

	"github.com/ProtonMail/proton-bridge/v3/internal/bridge"
	"github.com/ProtonMail/proton-bridge/v3/internal/events"
	"github.com/ProtonMail/proton-bridge/v3/internal/updater"
)

const maxNotices = 50

const (
	levelInfo    = "info"
	levelWarning = "warning"
	levelError   = "error"
)

type notice struct {
	ID    int       `json:"id"`
	Time  time.Time `json:"time"`
	Level string    `json:"level"`
	Text  string    `json:"text"`
}

type syncStatus struct {
	Progress    float64 `json:"progress"`
	RemainingMS int64   `json:"remaining_ms"`
}

// eventState collects what the bridge events tell about the app, so the web page can poll it.
type eventState struct {
	lock sync.RWMutex

	syncs     map[string]syncStatus
	badEvents map[string]string

	notices      []notice
	nextNoticeID int

	updateTarget  updater.Release
	restartNeeded bool
}

func newEventState() *eventState {
	return &eventState{
		syncs:     make(map[string]syncStatus),
		badEvents: make(map[string]string),
	}
}

func (state *eventState) addNotice(level, format string, args ...any) {
	state.lock.Lock()
	defer state.lock.Unlock()

	state.nextNoticeID++

	state.notices = append(state.notices, notice{
		ID:    state.nextNoticeID,
		Time:  time.Now(),
		Level: level,
		Text:  fmt.Sprintf(format, args...),
	})

	if len(state.notices) > maxNotices {
		state.notices = state.notices[len(state.notices)-maxNotices:]
	}
}

func (state *eventState) dismissNotice(id int) {
	state.lock.Lock()
	defer state.lock.Unlock()

	for i, n := range state.notices {
		if n.ID == id {
			state.notices = append(state.notices[:i], state.notices[i+1:]...)
			return
		}
	}
}

func (state *eventState) getNotices() []notice {
	state.lock.RLock()
	defer state.lock.RUnlock()

	return append([]notice{}, state.notices...)
}

func (state *eventState) getSync(userID string) (syncStatus, bool) {
	state.lock.RLock()
	defer state.lock.RUnlock()

	status, ok := state.syncs[userID]

	return status, ok
}

func (state *eventState) getBadEvent(userID string) string {
	state.lock.RLock()
	defer state.lock.RUnlock()

	return state.badEvents[userID]
}

func (state *eventState) clearBadEvent(userID string) {
	state.lock.Lock()
	defer state.lock.Unlock()

	delete(state.badEvents, userID)
}

func (state *eventState) getUpdateTarget() updater.Release {
	state.lock.RLock()
	defer state.lock.RUnlock()

	return state.updateTarget
}

func (state *eventState) isRestartNeeded() bool {
	state.lock.RLock()
	defer state.lock.RUnlock()

	return state.restartNeeded
}

func (state *eventState) modify(fn func()) {
	state.lock.Lock()
	defer state.lock.Unlock()

	fn()
}

// watchEvents records the bridge events in the event state until the event channel is closed.
func (s *Server) watchEvents() {
	for _, err := range s.bridge.GetErrors() {
		switch {
		case errors.Is(err, bridge.ErrVaultInsecure):
			s.state.addNotice(levelWarning, "No keychain is available, so the vault that stores Bridge settings and accounts is not encrypted.")

		case errors.Is(err, bridge.ErrVaultCorrupt):
			s.state.addNotice(levelError, "The vault that stores Bridge settings and accounts was corrupt and has been reset.")
		}
	}

	for event := range s.eventCh {
		s.handleEvent(event)
	}
}

func (s *Server) handleEvent(event events.Event) { //nolint:funlen,gocyclo
	switch event := event.(type) {
	case events.IMAPServerError:
		s.state.addNotice(levelError, "The IMAP server could not start: %v. Choose another IMAP port in the settings.", event.Error)

	case events.SMTPServerError:
		s.state.addNotice(levelError, "The SMTP server could not start: %v. Choose another SMTP port in the settings.", event.Error)

	case events.UserDeauth:
		s.state.modify(func() { delete(s.state.syncs, event.UserID) })

		if user, err := s.bridge.GetUserInfo(event.UserID); err == nil {
			s.state.addNotice(levelWarning, "Account %s was disconnected. Sign in again to resume.", user.Username)
		}

	case events.UserLoggedOut:
		s.state.modify(func() {
			delete(s.state.syncs, event.UserID)
			delete(s.state.badEvents, event.UserID)
		})

	case events.UserDeleted:
		s.state.modify(func() {
			delete(s.state.syncs, event.UserID)
			delete(s.state.badEvents, event.UserID)
		})

	case events.UserBadEvent:
		s.state.modify(func() { s.state.badEvents[event.UserID] = event.Error.Error() })

	case events.IMAPLoginFailed:
		s.state.addNotice(levelWarning, "An email client failed to sign in to IMAP as %s. Check that it uses the Bridge password.", event.Username)

	case events.UserAddressDisabled:
		s.state.addNotice(levelInfo, "Address %s was disabled.", event.Email)

	case events.UserAddressDeleted:
		s.state.addNotice(levelInfo, "Address %s was deleted.", event.Email)

	case events.SyncStarted:
		s.state.modify(func() { s.state.syncs[event.UserID] = syncStatus{} })

	case events.SyncProgress:
		s.state.modify(func() {
			s.state.syncs[event.UserID] = syncStatus{Progress: event.Progress, RemainingMS: event.Remaining.Milliseconds()}
		})

	case events.SyncFinished:
		s.state.modify(func() { delete(s.state.syncs, event.UserID) })

	case events.SyncFailed:
		if errors.Is(event.Error, context.Canceled) {
			s.state.modify(func() { delete(s.state.syncs, event.UserID) })
		}

	case events.UpdateAvailable:
		switch {
		case !event.Compatible:
			s.state.addNotice(levelWarning, "Bridge %s is available but cannot be installed automatically. Download it from https://proton.me/mail/bridge.", event.GetLatestVersion())

		case !event.Silent:
			s.state.modify(func() { s.state.updateTarget = event.Release })
		}

	case events.UpdateInstalled:
		s.state.modify(func() {
			s.state.updateTarget = updater.Release{}
			s.state.restartNeeded = true
		})

	case events.UpdateFailed:
		s.state.addNotice(levelError, "The update could not be installed: %v", event.Error)

	case events.UpdateForced:
		s.state.addNotice(levelError, "This version of Bridge is no longer supported. Download the latest version from https://proton.me/mail/bridge.")

	case events.TLSIssue:
		s.state.addNotice(levelWarning, "Bridge could not verify the TLS certificate of the Proton servers. Your network may be intercepting connections.")

	case events.UserNotification:
		s.state.addNotice(levelInfo, "%s: %s %s", event.Title, event.Subtitle, event.Body)
	}
}
