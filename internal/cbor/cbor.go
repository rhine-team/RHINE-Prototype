package cbor

import (
	//"log"
	//"reflect"

	"github.com/fxamacker/cbor/v2"
	"google.golang.org/grpc/encoding"
)

var (
	EMode cbor.EncMode
	DMode cbor.DecMode
)

func init() {
	//optsEnc := cbor.CanonicalEncOptions()
	optsEnc := cbor.CoreDetEncOptions()
	optsDec := cbor.DecOptions{MaxArrayElements: 2147483647}

	EMode, _ = optsEnc.EncMode()
	DMode, _ = optsDec.DecMode()

	encoding.RegisterCodec(&CBOR{})
}

type CBOR struct{}

func (_ CBOR) Name() string {
	return "cbor"
}

func (c CBOR) Marshal(v interface{}) ([]byte, error) {
	//log.Println("=================CBOR MESSAGE BEGIN=============")
	//log.Printf("Type of message: %T\n", v)
	//log.Println("Flat size before enc:", reflect.TypeOf(v).Size())
	res, err := EMode.Marshal(v)
	//log.Println("Encoded length: ", len(res), "bytes")
	//log.Println("=================CBOR MESSAGE END=============")
	return res, err
}

func (c CBOR) Unmarshal(data []byte, v interface{}) error {
	if data == nil {
		return nil
	}

	return DMode.Unmarshal(data, v)
}

func MarshalS(v interface{}) ([]byte, error) {
	//log.Println("=================CBOR MESSAGE BEGIN=============")
	//log.Printf("Type of message: %T\n", v)
	//log.Println("Flat size before enc:", reflect.TypeOf(v).Size())
	res, err := EMode.Marshal(v)
	//log.Println("Encoded length: ", len(res), "bytes")
	//log.Println("=================CBOR MESSAGE END=============")
	return res, err
}

func UnmarshalS(data []byte, v interface{}) error {
	if data == nil {
		return nil
	}

	return DMode.Unmarshal(data, v)
}
