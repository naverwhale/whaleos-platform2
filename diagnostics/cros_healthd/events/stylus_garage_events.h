// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EVENTS_STYLUS_GARAGE_EVENTS_H_
#define DIAGNOSTICS_CROS_HEALTHD_EVENTS_STYLUS_GARAGE_EVENTS_H_

#include <mojo/public/cpp/bindings/pending_remote.h>

#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"

namespace diagnostics {

// Interface which allows clients to subscribe to stylus garage events.
class StylusGarageEvents {
 public:
  virtual ~StylusGarageEvents() = default;

  // Adds a new observer to be notified when stylus garage events occur.
  virtual void AddObserver(
      mojo::PendingRemote<ash::cros_healthd::mojom::EventObserver>
          observer) = 0;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EVENTS_STYLUS_GARAGE_EVENTS_H_
