package agent

import "testing"

func TestParseClientsJSON(t *testing.T) {
	raw := `[{"id":"alice|1710000000","commonName":"alice","remoteIp":"1.2.3.4:12345","virtualIp":"10.8.0.2","connectedAt":"1710000000","rxBytes":100,"txBytes":200}]`
	got, err := parseClientsJSON([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].CommonName != "alice" || got[0].VirtualIP != "10.8.0.2" {
		t.Fatalf("got %+v", got)
	}
}
