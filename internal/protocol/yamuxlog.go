package protocol

import (
	"fmt"
	"log/slog"

	"github.com/hashicorp/yamux"
)

// YamuxLogger routes the multiplexor's diagnostics into slog so a single log
// stream covers the whole process, instead of yamux writing straight to stderr.
//
// Note that yamux refuses a Config with both LogOutput and Logger set, so
// callers must clear LogOutput on the config they build from DefaultConfig.
func YamuxLogger(log *slog.Logger, attrs ...any) yamux.Logger {
	return &slogYamux{log: log.With(attrs...)}
}

type slogYamux struct {
	log *slog.Logger
}

func (l *slogYamux) Print(v ...any)   { l.log.Debug(fmt.Sprint(v...)) }
func (l *slogYamux) Println(v ...any) { l.log.Debug(fmt.Sprintln(v...)) }
func (l *slogYamux) Printf(format string, v ...any) {
	l.log.Debug(fmt.Sprintf(format, v...))
}
