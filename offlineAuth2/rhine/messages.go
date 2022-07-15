package rhine

/*
import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
)


type DlgRequestCSR struct {
	Rid string	   `json:"rid"`
	Csr string     `json:"csr"`
}

type ApvMessage struct {
	SignatureApv string   `json:"signatureApv"`
	RCert        string   `json:"rCert"`
}

type RequestForRCert struct {
	Csr string            `json:"csr"`
	SignatureApv string   `json:"signatureApv"`
	RCert        string   `json:"rCert"`
}

type RequestForLogging struct {
	Csr string               `json:"csr"`
	SignatureApv string      `json:"signatureApv"`
	RCert        string      `json:"rCert"`
	PreRC        string      `json:"preRC"`
	Nds			*NDSMessage `json:"nds"`
}

type NDSMessage struct {
	Log     string    `json:"log"`
	Zone    string    `json:"zone"`
	Al      string    `json:"al"`
	TbsCert string    `json:"tbsCert"`
	Exp     string    `json:"exp"`
}


type PublicKeyJSON struct {
	Algorithm        string `json:"algorithm"`
	Pubkey           string `json:"pubkey"`

}




// Creates a rid given a csr
func (csr *Csr) createRID() {
	hasher := sha256.New()
	// ZN
	hasher.Write([]byte(csr.zone.Name))
	// pk
	hasher.Write(MarshalPublicKey(csr.zone.Pubkey.Public()))
	// al
	hasher.Write([]byte(csr.al))

	// aux
	timeBinary, err := csr.exp.MarshalBinary()
	if err != nil {
		println(err)
		//TODO
	}
	hasher.Write(timeBinary)

	// A
	hasher.Write([]byte(csr.ca.Name))
	// L
	hasher.Write([]byte(csr.log.Name))
	csr.rid = hasher.Sum(nil)
}

// Marshal different PublicKeys into bytes
func MarshalPublicKey(pub crypto.PublicKey) bytes[] {
	res := []byte{}
	switch key.Public().(type) {
		case *rsa.PublicKey:
			// TODO
		case ed25519.PublicKey:
			// TODO
	}
}

*/
