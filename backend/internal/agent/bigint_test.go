package agent

import "testing"

func TestBigIntValUint64(t *testing.T) {
	if got := bigIntVal(uint64(12345)); got != 12345 {
		t.Fatalf("uint64: got %d", got)
	}
	if got := bigIntVal(float64(99)); got != 99 {
		t.Fatalf("float64: got %d", got)
	}
	if got := bigIntVal("nope"); got != 0 {
		t.Fatalf("string: got %d", got)
	}
}
