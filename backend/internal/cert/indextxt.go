package cert

import (
	"fmt"
	"strings"
	"time"
)

type IndexCertRow struct {
	CommonName   string
	SerialNumber string
	ExpiresAt    time.Time
	RevokedAt    *time.Time
}

func BuildIndexTxt(rows []IndexCertRow) string {
	var out []string
	for _, row := range rows {
		serialHex := NormalizeSerialHex(row.SerialNumber)
		if serialHex == "" {
			serialHex = "01"
		}
		exp := toOpenSSLUTC(row.ExpiresAt)
		cn := strings.ReplaceAll(row.CommonName, "\t", " ")
		if row.RevokedAt != nil {
			rev := toOpenSSLUTC(*row.RevokedAt)
			out = append(out, fmt.Sprintf("R\t%s\t%s\t%s\tunknown\t/CN=%s", exp, rev, serialHex, cn))
		} else {
			out = append(out, fmt.Sprintf("V\t%s\t\t%s\tunknown\t/CN=%s", exp, serialHex, cn))
		}
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n") + "\n"
}

func toOpenSSLUTC(d time.Time) string {
	if d.IsZero() {
		return "00000000000000Z"
	}
	y := d.UTC().Year() % 100
	return fmt.Sprintf("%02d%02d%02d%02d%02d%02dZ",
		y, int(d.UTC().Month()), d.UTC().Day(),
		d.UTC().Hour(), d.UTC().Minute(), d.UTC().Second())
}
