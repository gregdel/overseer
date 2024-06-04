package main

import (
	"context"
	"errors"
	"fmt"
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
		fmt.Println("failed to get perf reader", err)
		return
	}
	defer reader.Close()

	fmt.Println("Starting to read perf events...")
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
				fmt.Println("failed to read perf event", err)
			}
			continue
		}

		if len(record.RawSample) != perfRecordSize {
			fmt.Printf("invalid sample size got %d expected %d\n",
				len(record.RawSample), perfRecordSize)
			continue
		}

		k := &key{}
		if err := k.UnmarshalBinary(record.RawSample[:k.size()]); err != nil {
			fmt.Println("failed to unmarshal event", err)
			continue
		}

		event := eventType(record.RawSample[k.size()])
		fmt.Printf("%s: %s\n", event, k)

		if record.LostSamples != 0 {
			fmt.Printf("lost %d record samples\n", record.LostSamples)
			return
		}
	}
}
