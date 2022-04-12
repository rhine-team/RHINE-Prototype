package rhine

import (
	"crypto/sha256"
	"github.com/cbergoon/merkletree"
)

type MPathProofType int

const (
	ProofOfPresence MPathProofType = 0
	ProofOfAbsence  MPathProofType = 1
)

type MPathProof struct {
	path  [][]byte
	ptype MPathProofType
}

type DSLeafZone struct {
	zone string
	alv  AuthorityLevel
}

type DSLeafContent struct {
	start DSLeafZone
	end   DSLeafZone
}

func (l DSLeafContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	msg := []byte(l.start.zone + l.start.alv.ToString() + l.end.zone + l.end.alv.ToString())
	_, err := h.Write(msg)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (l DSLeafContent) Equals(other merkletree.Content) (bool, error) {
	return l.start.zone == other.(DSLeafContent).start.zone && l.start.alv == other.(DSLeafContent).start.alv && l.end.zone == other.(DSLeafContent).end.zone && l.end.alv == other.(DSLeafContent).end.alv, nil
}
