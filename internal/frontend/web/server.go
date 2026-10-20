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

// Package web implements the web interface used to configure Bridge.
package web

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ProtonMail/gluon/async"
	"github.com/ProtonMail/proton-bridge/v3/internal/bridge"
	"github.com/ProtonMail/proton-bridge/v3/internal/events"
	"github.com/ProtonMail/proton-bridge/v3/pkg/restarter"
	"github.com/sirupsen/logrus"
)

//go:embed static
var staticFiles embed.FS

const shutdownTimeout = 5 * time.Second

// Server serves the web interface.
type Server struct {
	bridge       *bridge.Bridge
	restarter    *restarter.Restarter
	panicHandler async.PanicHandler
	eventCh      <-chan events.Event
	quitCh       <-chan struct{}

	address string
	useTLS  bool

	auth  *authenticator
	state *eventState

	logins     map[string]*accountLogin
	loginsLock sync.Mutex

	// stopCh is closed when the web interface asks Bridge to restart.
	stopCh   chan struct{}
	stopOnce sync.Once

	log *logrus.Entry
}

// New creates the web interface server for the given bridge.
// The server listens on address, and serves HTTPS with the Bridge TLS certificate unless useTLS is false.
func New(
	b *bridge.Bridge,
	restarter *restarter.Restarter,
	panicHandler async.PanicHandler,
	eventCh <-chan events.Event,
	quitCh <-chan struct{},
	address string,
	useTLS bool,
) *Server {
	return &Server{
		bridge:       b,
		restarter:    restarter,
		panicHandler: panicHandler,
		eventCh:      eventCh,
		quitCh:       quitCh,

		address: address,
		useTLS:  useTLS,

		auth:  newAuthenticator(b),
		state: newEventState(),

		logins: make(map[string]*accountLogin),

		stopCh: make(chan struct{}),

		log: logrus.WithField("pkg", "frontend/web"),
	}
}

// Loop serves the web interface until Bridge quits or the web interface asks for a restart.
func (s *Server) Loop() error {
	listener, err := s.listen()
	if err != nil {
		return err
	}

	server := &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		defer async.HandlePanic(s.panicHandler)
		s.watchEvents()
	}()

	errCh := make(chan error, 1)

	go func() {
		defer async.HandlePanic(s.panicHandler)
		errCh <- server.Serve(listener)
	}()

	scheme := "https"
	if !s.useTLS {
		scheme = "http"
	}

	s.log.WithField("address", listener.Addr().String()).Info("Web interface started")
	fmt.Printf("The Bridge web interface is available at %s://%s\n", scheme, listener.Addr().String())

	if token := s.auth.getSetupToken(); token != "" {
		// The token is written to the log as well, because standard output is not visible when the launcher runs without a console.
		s.log.WithField("setupToken", token).Warn("The web interface password is not set; enter the setup token in the web interface to choose one")
		fmt.Printf("Open the web interface and enter this setup token to choose a password: %s\n", token)
	}

	select {
	case <-s.quitCh:
	case <-s.stopCh:
	case err := <-errCh:
		return fmt.Errorf("web interface stopped: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("could not stop web interface: %w", err)
	}

	return nil
}

func (s *Server) listen() (net.Listener, error) {
	listener, err := net.Listen("tcp", s.address)
	if err != nil {
		return nil, fmt.Errorf("could not listen on %s: %w", s.address, err)
	}

	if !s.useTLS {
		return listener, nil
	}

	certPEM, keyPEM := s.bridge.GetBridgeTLSCert()

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("could not load the Bridge TLS certificate: %w", err)
	}

	return tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}), nil
}

// restart asks Bridge to restart by stopping the web interface.
func (s *Server) restart() {
	s.restarter.Set(true, false)
	s.stopOnce.Do(func() { close(s.stopCh) })
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	static, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}

	mux.Handle("GET /", http.FileServerFS(static))

	mux.HandleFunc("GET /api/session", s.handleSession)
	mux.HandleFunc("POST /api/setup", s.handleSetup)
	mux.HandleFunc("POST /api/signin", s.handleSignIn)
	mux.HandleFunc("POST /api/signout", s.withSession(s.handleSignOut))
	mux.HandleFunc("POST /api/password", s.withSession(s.handleChangePassword))

	mux.HandleFunc("GET /api/status", s.withSession(s.handleStatus))
	mux.HandleFunc("POST /api/settings", s.withSession(s.handleSettings))
	mux.HandleFunc("POST /api/notices/{id}/dismiss", s.withSession(s.handleDismissNotice))
	mux.HandleFunc("POST /api/updates/check", s.withSession(s.handleCheckUpdates))
	mux.HandleFunc("POST /api/updates/install", s.withSession(s.handleInstallUpdate))
	mux.HandleFunc("POST /api/restart", s.withSession(s.handleRestart))

	mux.HandleFunc("POST /api/accounts/login", s.withSession(s.handleAccountLogin))
	mux.HandleFunc("POST /api/accounts/login/hv", s.withSession(s.handleAccountLoginHV))
	mux.HandleFunc("POST /api/accounts/login/totp", s.withSession(s.handleAccountLoginTOTP))
	mux.HandleFunc("POST /api/accounts/login/mailbox", s.withSession(s.handleAccountLoginMailbox))
	mux.HandleFunc("POST /api/accounts/login/abort", s.withSession(s.handleAccountLoginAbort))
	mux.HandleFunc("POST /api/accounts/{id}/signout", s.withSession(s.handleAccountSignOut))
	mux.HandleFunc("POST /api/accounts/{id}/remove", s.withSession(s.handleAccountRemove))
	mux.HandleFunc("POST /api/accounts/{id}/mode", s.withSession(s.handleAccountMode))
	mux.HandleFunc("POST /api/accounts/{id}/bad-event", s.withSession(s.handleAccountBadEvent))

	return withSecurityHeaders(mux)
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")

		next.ServeHTTP(w, r)
	})
}
