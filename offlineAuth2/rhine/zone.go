package rhine

import "crypto"

type ZoneOwner struct {
	Name   string
	Pubkey crypto.Signer
}

type AuthorityLevel int

const (
	IND AuthorityLevel = 0
	TER AuthorityLevel = 1
	EOI AuthorityLevel = 2
	DOL AuthorityLevel = 3
)
