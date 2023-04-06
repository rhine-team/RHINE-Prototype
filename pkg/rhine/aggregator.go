package rhine

import (
	"crypto"
)

type Agg struct {
	Name   string
	Pubkey crypto.PublicKey
}
