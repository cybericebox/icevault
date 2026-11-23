//go:build harness && !desktop

package main

import (
	"context"
	"sync"
	"time"

	"github.com/cybericebox/icevault/internal/update"
)

// harnessUpdater plays the updates of the window in the harness (--update): a newer release is found, the download runs for a few seconds, and Apply
// changes nothing on disk. "manual" plays a copy that cannot be replaced, "failed" a download whose sum does not match.
type harnessUpdater struct {
	mu   sync.Mutex
	mode string
	st   update.Status
}

func newHarnessUpdater(mode string) *harnessUpdater {
	return &harnessUpdater{mode: mode, st: update.Status{State: update.Idle, Current: "v0.3.0", Auto: true}}
}

func (h *harnessUpdater) Status() update.Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.st
}

func (h *harnessUpdater) Check(context.Context) update.Status {
	time.Sleep(600 * time.Millisecond)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.st.Latest, h.st.URL, h.st.Checked = "v0.4.0", "https://github.com/"+update.Repo+"/releases/tag/v0.4.0", time.Now().UTC().Format(time.RFC3339)
	switch h.mode {
	case "current":
		h.st.Latest, h.st.State = "v0.3.0", update.Current
	case "manual":
		h.st.State, h.st.Code = update.Manual, "update_not_writable"
	default:
		h.st.State = update.Available
	}
	return h.st
}

func (h *harnessUpdater) Fetch(context.Context) (update.Status, error) {
	h.mu.Lock()
	h.st.State, h.st.Progress, h.st.Code = update.Downloading, 0, ""
	st := h.st
	h.mu.Unlock()
	go func() {
		for p := 0; p <= 99; p += 7 {
			time.Sleep(200 * time.Millisecond)
			h.mu.Lock()
			h.st.Progress = p
			h.mu.Unlock()
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.mode == "failed" {
			h.st.State, h.st.Code, h.st.Progress = update.Failed, "update_bad_sum", 0
			return
		}
		h.st.State, h.st.Progress = update.Ready, 100
	}()
	return st, nil
}

func (h *harnessUpdater) Apply() error { return nil }

func (h *harnessUpdater) SetAuto(on bool) update.Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.st.Auto = on
	return h.st
}

func (h *harnessUpdater) Due() bool { return h.Status().Auto }
