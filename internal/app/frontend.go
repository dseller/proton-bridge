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

package app

import (
	"github.com/ProtonMail/proton-bridge/v3/internal/bridge"
	"github.com/ProtonMail/proton-bridge/v3/internal/crash"
	"github.com/ProtonMail/proton-bridge/v3/internal/events"
	"github.com/ProtonMail/proton-bridge/v3/internal/frontend/web"
	"github.com/ProtonMail/proton-bridge/v3/pkg/restarter"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

func runFrontend(
	c *cli.Context,
	crashHandler *crash.Handler,
	restarter *restarter.Restarter,
	bridge *bridge.Bridge,
	eventCh <-chan events.Event,
	quitCh <-chan struct{},
) error {
	logrus.Debug("Running frontend")
	defer logrus.Debug("Frontend stopped")

	return web.New(bridge, restarter, crashHandler, eventCh, quitCh, c.String(flagWebAddress), !c.Bool(flagWebNoTLS)).Loop()
}
