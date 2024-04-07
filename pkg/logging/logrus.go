package logging

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"os"
	"path"
	"runtime"
	"sync"
)

var e *logrus.Entry
var once sync.Once

func GetLogger() Logger {
	once.Do(Init)
	return e
}

func Init() {
	l := logrus.New()
	l.SetReportCaller(true)
	l.Formatter = &logrus.TextFormatter{
		TimestampFormat: "02-01-2006 15:04:05.000",
		FullTimestamp:   true,
		DisableColors:   false,
		ForceColors:     true,
		PadLevelText:    true,
		CallerPrettyfier: func(frame *runtime.Frame) (function string, file string) {
			return fmt.Sprintf("%s()", frame.Function), fmt.Sprintf(" [%s:%d]", path.Base(frame.File), frame.Line)
		},
	}

	err := os.MkdirAll("logs", 0744)
	if err != nil {
		panic(err)
	}

	logFile, err := os.OpenFile("logs/info.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return
	}

	l.SetOutput(io.Discard)

	l.AddHook(&writerHook{
		Writer:    []io.Writer{logFile, os.Stdout},
		LogLevels: logrus.AllLevels,
	})

	switch os.Getenv("LOG_LEVEL") {
	case Trace:
		l.SetLevel(logrus.TraceLevel)
	case Debug:
		l.SetLevel(logrus.DebugLevel)
	case Info:
		l.SetLevel(logrus.InfoLevel)
	case Warn:
		l.SetLevel(logrus.WarnLevel)
	case Error:
		l.SetLevel(logrus.ErrorLevel)
	default:
		l.SetLevel(logrus.DebugLevel)
	}

	e = logrus.NewEntry(l)
}

type writerHook struct {
	Writer    []io.Writer
	LogLevels []logrus.Level
}

func (h *writerHook) Levels() []logrus.Level {
	return h.LogLevels
}

func (h *writerHook) Fire(entry *logrus.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}
	for _, writer := range h.Writer {
		_, err = writer.Write([]byte(line))
	}
	return err
}
