package cbor

import (
	"github.com/fxamacker/cbor/v2"
	"google.golang.org/grpc/encoding"
)

var (
	EMode cbor.EncMode
	DMode cbor.DecMode
)

func init() {
	optsEnc := cbor.CanonicalEncOptions()
	optsDec := cbor.DecOptions{}

	EMode, _ = optsEnc.EncMode()
	DMode, _ = optsDec.DecMode()

	encoding.RegisterCodec(&CBOR{})
}

type CBOR struct{}

func (_ CBOR) Name() string {
	return "cbor"
}

func (c CBOR) Marshal(v interface{}) ([]byte, error) {
	return EMode.Marshal(v)
}

func (c CBOR) Unmarshal(data []byte, v interface{}) error {
	if data == nil {
		return nil
	}

	return DMode.Unmarshal(data, v)
}
