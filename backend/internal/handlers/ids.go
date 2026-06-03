package handlers

import "github.com/segmentio/ksuid"

func newID() string {
	return ksuid.New().String()
}
