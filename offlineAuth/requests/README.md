## NewDlg Request

json object containing keys:
- *header*
- *payload*
- *signature*

```
{
   "header":
    {
     "parent_auth_type": "certificate" / "dnssec",
     "parent_cert": urlsafe_base64(bytes(Certificate)),
     "alg": "Ed25519" / "RSA",
     "pubkey": urlsafe_base64(bytes(PublicKey))
    }, 
   "payload": 
    {
      "req_type":"NewDlgReq",
      "csr": urlsafe_base64(bytes(CertificateSigningRequest)),
    },
   "signature": urlsafe_base64(bytes(Signature))
}

```

**Signature**:  base64 encoded signature. Message to sign is ***bytes(json(header))||bytes(json(payload))***, signed with the secret key for public key in certificate in header
**pubkey**: encoding RSA: PKCS1 Public Key, encoding Ed25519: PKIX Public Key 


### CaResponse:
```
{ 
   "cert": urlsafebase64(bytes(certificate)),
   "error": string
}
```

