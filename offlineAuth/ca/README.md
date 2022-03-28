# CA Server

`go run run_ca.go [ConfigPath]`

## Config: 

```
{
    "PrivateKeyAlgorithm": "RSA",
    "PrivateKeyPath": "data/privkey.pem",
    "CertificatePath": "data/cacert.pem",
    "MapServerAddress": "172.18.0.5:8094",
    "MapServerPublicKeyPath": "data/mappk1.pem",
    "MapId": 5250323035397941290, 
    "ServerAddress" : "localhost:10000",  // Address of CA 
    "RootCertsPath" : "roots/"  // Certificates in this directory are added to the Cert Pool
}
```