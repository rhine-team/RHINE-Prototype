package main

import "fmt"


const (
	RCERTprefix = "rhine_cert="

)


func main() {
	base64cert := "MIIBNTCB6KADAgECAgF7MAUGAytlcDAbMRkwFwYDVQQDExBSSElORSBFWEFNUExFIENBMB4XDTIyMDMwODExMzgyM1oXDTIzMDIyNzExMzgyM1owADAqMAUGAytlcAMhANPAkOIwN8C9gGM8z4q+EHFhPVrWDkSlBEUAV2A3qhDFo2wwajAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBRdwkfb0TZ6BS5J2EkWjL+QlAOVzDAaBgNVHREBAf8EEDAOggxyaGluZS1ucy5jb20wDQYEK4N0CQQFMAMBAf8wBQYDK2VwA0EAEsRHB0c0IYnZFwsdx8m4RgyXqmqzvXaIwAFHSQjO1rgDwt9bBgttpUL14Zi0Pnm5JQmpaYnMOQJGD6QHk8FcDA=="
	base64sig := "nl3C38n2+74UEzQr71dhzF5+2OsIf4a1El8U8t59oNTsBtgoWRXZXdNLIUvMEyy48dPYmOAdK5xA1fjuUhekAA=="

	fmt.Println(convertRCert(base64cert))
	fmt.Println(convertAssertion(base64sig, "assertion_ip4=[192.168.1.1]"))

}

func convertRCert(in string) string  {

	fullstr := RCERTprefix + in
	split := split255TXT(fullstr)

	res := ""
	for _ , chunk := range split{
		res += "\""
		res += chunk
		res += "\" "
	}
	return res
}

func convertAssertion(sig string, assertion string) string  {

	fullstr := assertion + " " + sig
	split := split255TXT(fullstr)

	res := ""
	for _ , chunk := range split{
		res += "\""
		res += chunk
		res += "\" "
	}
	return res
}


func split255TXT (in string) []string {
	tmp := in
	res := []string{}

	for (len(tmp) > 255) {
		res = append(res, tmp[:255])
		tmp = tmp[255:]

	}

	if len(tmp) > 0 {
		res = append(res, tmp)
	}
	return res
}