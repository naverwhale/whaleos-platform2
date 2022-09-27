// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EVENTS_AUDIO_EVENTS_IMPL_H_
#define DIAGNOSTICS_CROS_HEALTHD_EVENTS_AUDIO_EVENTS_IMPL_H_

#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/remote_set.h>

#include "diagnostics/cros_healthd/events/audio_events.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "mojo/cros_healthd_events.mojom.h"

namespace diagnostics {

// Production implementation of the AudioEvents interface.
class AudioEventsImpl final : public AudioEvents {
 public:
  explicit AudioEventsImpl(Context* context);
  AudioEventsImpl(const AudioEventsImpl&) = delete;
  AudioEventsImpl& operator=(const AudioEventsImpl&) = delete;
  ~AudioEventsImpl() = default;

  void AddObserver(mojo::PendingRemote<
                   chromeos::cros_healthd::mojom::CrosHealthdAudioObserver>
                       observer) override;

 private:
  void OnUnderrunSignal();
  void OnSevereUnderrunSignal();

  // Each observer in |observers_| will be notified of any audio event in the
  // chromeos::cros_healthd::mojom::CrosHealthdAudioObserver interface. The
  // RemoteSet manages the lifetime of the endpoints, which are
  // automatically destroyed and removed when the pipe they are bound to is
  // destroyed.
  mojo::RemoteSet<chromeos::cros_healthd::mojom::CrosHealthdAudioObserver>
      observers_;

  // Unowned pointer. Should outlive this instance.
  Context* const context_ = nullptr;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EVENTS_AUDIO_EVENTS_IMPL_H_
