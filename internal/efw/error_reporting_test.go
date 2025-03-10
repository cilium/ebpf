//go:build windows

package efw

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestConfigureErrorReporting(t *testing.T) {
	qt.Assert(t, qt.ErrorIs(configureCRTErrorReporting(), errErrorReportingAlreadyConfigured))
}

func TestIsDebuggerPresent(t *testing.T) {
	qt.Assert(t, qt.IsFalse(isDebuggerPresent()))
}
