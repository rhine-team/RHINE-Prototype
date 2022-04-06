package rhine

import "crypto"

type Log struct {
	Name   string
	Pubkey crypto.PublicKey
}

// add list of available logs
