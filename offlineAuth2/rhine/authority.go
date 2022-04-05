package rhine

import "crypto"

type Authority struct {
	Name   string
	Pubkey crypto.PublicKey
}
