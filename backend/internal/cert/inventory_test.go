package cert

import "testing"

func TestParseEasyRsaIndexLine(t *testing.T) {
	line := "V\t251231120000Z\t\t0A1B2C\tunknown\t/CN=test-user"
	e := ParseEasyRsaIndexLine(line)
	if e == nil {
		t.Fatal("expected parse")
	}
	if e.cn != "test-user" || e.status != "V" || e.serialHex != "A1B2C" {
		t.Fatalf("unexpected entry: %+v", e)
	}
	if ParseEasyRsaIndexLine("R\t251231120000Z\t251231120000Z\t0A1B2C\tunknown\t/CN=revoked") == nil {
		t.Fatal("expected revoked line parse")
	}
	if ParseEasyRsaIndexLine("# comment") != nil {
		t.Fatal("comment should be nil")
	}
}

func TestNormalizeSerialHex(t *testing.T) {
	if NormalizeSerialHex("00A1") != "A1" {
		t.Fatalf("got %q", NormalizeSerialHex("00A1"))
	}
}
