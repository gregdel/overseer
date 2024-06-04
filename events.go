package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/cilium/ebpf/perf"
)

type eventType uint8

const (
	eventTypeNew eventType = iota
	eventTypeFail
)

func (e eventType) String() string {
	switch e {
	case eventTypeNew:
		return "NEW"
	case eventTypeFail:
		return "FAIL"
	default:
		return "UNKNOWN"
	}
}

func (app *app) readEvents(ctx context.Context) {
	reader, err := perf.NewReader(app.ebpf.Events, os.Getpagesize())
	if err != nil {
		logErr("perf_events", "Failed to get reader: %s\n", err)
		return
	}
	defer reader.Close()

	logInfo("perf_events", "Starting to read events\n")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		reader.SetDeadline(time.Now().Add(time.Second))

		record, err := reader.Read()
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				logErr("perf_events", "Failed to read event: %s\n", err)
			}
			continue
		}

		if len(record.RawSample) != perfRecordSize {
			logErr("perf_events", "Invalid sample size, got %d expected %d\n",
				len(record.RawSample), perfRecordSize)
			continue
		}

		k := &key{}
		if err := k.UnmarshalBinary(record.RawSample[:k.size()]); err != nil {
			logErr("perf_events", "Failed to unmarshal key: %s\n", err)
			continue
		}

		event := eventType(record.RawSample[k.size()])
		logInfo("perf_events", "%s %s\n", event, k)

		if record.LostSamples != 0 {
			logInfo("perf_events", "Lost %d record samples\n", record.LostSamples)
			return
		}
	}
}
