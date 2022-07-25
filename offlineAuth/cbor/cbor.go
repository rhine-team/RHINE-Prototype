package cbor

import (
	"github.com/fxamacker/cbor/v2"
	"google.golang.org/grpc/encoding"
)

var (
	eMode cbor.EncMode
	dMode cbor.DecMode
)

func init() {
	optsEnc := cbor.CanonicalEncOptions()
	optsDec := cbor.DecOptions{}

	eMode, _ = optsEnc.EncMode()
	dMode, _ = optsDec.DecMode()

	encoding.RegisterCodec(&CBOR{})
}

type CBOR struct{}

func (_ CBOR) Name() string {
	return "cbor"
}

func (c CBOR) Marshal(v interface{}) ([]byte, error) {
	return eMode.Marshal(v)
}

func (c CBOR) Unmarshal(data []byte, v interface{}) error {
	if data == nil {
		return nil
	}

	return dMode.Unmarshal(data, v)
}
