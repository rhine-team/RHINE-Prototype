package rhine

import (
	"crypto"
	"fmt"
	"log"
)

type ZoneOwner struct {
	Name   string
	Pubkey crypto.PublicKey
}

type AuthorityLevelFlag uint8
type AuthorityLevel uint8

const (
	IND AuthorityLevelFlag = 0b0001
	EOI AuthorityLevelFlag = 0b0010
	TER AuthorityLevelFlag = 0b0100
	DOL AuthorityLevelFlag = 0b1000
)

func (al AuthorityLevelFlag) ToString() string {
	switch al {
	case IND:
		return "IND"
	case TER:
		return "TER"
	case EOI:
		return "EOI"
	case DOL:
		return "DOL"
	default:
		return "NONE"
	}

}

func (al AuthorityLevel) ToString() string {
	return fmt.Sprintf("%b", al)
}

func (al AuthorityLevel) CheckINDSet() bool {
	return 0b1&al == 1
}

func (al AuthorityLevel) CheckEOISet() bool {
	return 0b1&(al>>1) == 1
}

func (al AuthorityLevel) CheckTERSet() bool {
	return 0b1&(al>>2) == 1
}

func (al AuthorityLevel) CheckDOLSet() bool {
	return 0b1&(al>>3) == 1
}

func CheckINDSetAlt(al AuthorityLevel) bool {
	return 0b1&al == 1
}

func CheckEOISetAlt(al AuthorityLevel) bool {
	return 0b1&(al>>1) == 1
}

func CheckTERSetAlt(al AuthorityLevel) bool {
	return 0b1&(al>>2) == 1
}

func CheckDOLSetAlt(al AuthorityLevel) bool {
	return 0b1&(al>>3) == 1
}

func (al AuthorityLevel) CheckLegalAuthLevel() bool {
	// TODO: Check this again!
	return true
	//return al == 0b0000 || al == 0b0011 || al == 0b0011 || al == 0b0101 || al == 0b1001 || al == 0b0001
}

// Check legal delegation
func CheckLegalDelegationAuthority(parentAL AuthorityLevel, childAL AuthorityLevel) bool {
	log.Println("Parent, then Child AL: ", parentAL, childAL)

	// Check if flag combination is legal
	res := true
	//res = parentAL.CheckLegalAuthLevel() && childAL.CheckLegalAuthLevel()
	if !res {
		return false
	}

	/*
		if parentAL.CheckEOISet() {
			// Child CANNOT be independent!
			return !childAL.CheckINDSet()
		} else if parentAL.CheckTERSet() {
			// parent is terminating, meaning no delegation is legit
			return false
		} else if parentAL.CheckDOLSet() {
			// parent is delegation only, TODO: check if legal
			return false
		} else if parentAL.CheckINDSet() {
			// parent is IND without further restrictions
			return true
		} else {
			// parent is NON-IND, should not be able to delegate
			return false
		}
	*/

	//TODO: Check this again!
	if !parentAL.CheckINDSet() {
		log.Println("Failed because parent is non-IND!")
		return false
	}

	if parentAL.CheckDOLSet() {
		log.Println("Failed because parent is DOL")
		return false
	}
	return true
}
