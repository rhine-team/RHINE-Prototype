package ca

type Config struct {
	PrivateKeyAlgorithm    string
	PrivateKeyPath         string
	CertificatePath        string
	MapServerAddress       string
	MapServerPublicKeyPath string
	MapId                  int64
	ServerAddress 		   string
	RootCertsPath          string
}
