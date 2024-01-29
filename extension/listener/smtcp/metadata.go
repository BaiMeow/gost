package smtcp

import (
	"encoding/base64"
	md "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

type metadata struct {
	mptcp bool
	key   []byte
}

func (l *smtcpListener) parseMetadata(md md.Metadata) (err error) {
	l.md.mptcp = mdutil.GetBool(md, "mptcp")
	l.md.key, err = base64.StdEncoding.DecodeString(mdutil.GetString(md, "key"))
	return
}
