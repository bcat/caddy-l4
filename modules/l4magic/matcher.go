// Copyright 2024 VNXME
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package l4magic

import (
	"encoding/hex"
	"io"
	"slices"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchMagic{})
}

type MatchMagic struct {
	Start uint16 `json:"count,omitempty"`
	Bytes string `json:"bytes,omitempty"`

	parsed []byte
}

func (m *MatchMagic) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.magic",
		New: func() caddy.Module { return new(MatchMagic) },
	}
}

func (m *MatchMagic) Match(cx *layer4.Connection) (bool, error) {
	// Read a number of bytes
	count := int(m.Start) + len(m.parsed)
	buf := make([]byte, count)
	n, err := io.ReadFull(cx, buf)
	if err != nil || n < int(count) {
		return false, err
	}

	// Match these bytes against the magic bytes
	return slices.Compare(m.parsed, buf[m.Start:len(m.parsed)]) == 0, nil
}

func (m *MatchMagic) Provision(_ caddy.Context) (err error) {
	m.parsed, err = hex.DecodeString(m.Bytes)
	if err != nil {
		return err
	}
	return nil
}

// UnmarshalCaddyfile sets up the MatchMagic from Caddyfile tokens. Syntax:
//
//	magic <bytes> [<start>]
func (m *MatchMagic) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// One or two same-line argument must be provided
	if d.CountRemainingArgs() == 0 || d.CountRemainingArgs() > 2 {
		return d.ArgErr()
	}

	_, m.Bytes = d.NextArg(), d.Val()
	if d.NextArg() {
		val, err := strconv.ParseUint(d.Val(), 10, 16)
		if err != nil {
			return d.Errf("parsing %s start: %v", wrapper, err)
		}
		m.Start = uint16(val)
	}

	// No blocks are supported
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed %s option: blocks are not supported", wrapper)
	}

	return nil
}

var (
	_ caddy.Provisioner     = (*MatchMagic)(nil)
	_ caddyfile.Unmarshaler = (*MatchMagic)(nil)
	_ layer4.ConnMatcher    = (*MatchMagic)(nil)
)
