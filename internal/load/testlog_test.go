package load_test

import (
	"io"
	"log/slog"
)

// testLogger discards log output; tests assert on metrics, not on log lines.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}
