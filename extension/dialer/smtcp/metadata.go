package smtcp

import (
	"encoding/base64"
	mdutil "github.com/go-gost/core/metadata/util"
	"time"

	md "github.com/go-gost/core/metadata"
)

const (
	dialTimeout = "dialTimeout"
)

const (
	defaultDialTimeout = 5 * time.Second
)

type metadata struct {
	dialTimeout time.Duration
	key         []byte
}

func (d *tcpDialer) parseMetadata(md md.Metadata) (err error) {
	d.md.key, err = base64.StdEncoding.DecodeString(mdutil.GetString(md, "key"))
	return
}
