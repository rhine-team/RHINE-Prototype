### Build
```
go build
```

### Query
Enable rhine E2E validation with `-rhine` flag, also you need to specify the CA certificate file path with `-cert` flag.

**Example**:
```
./rdig -port 10003 -rhine -cert=./testdata/certificate/CACert.pem @localhost www.google.com
```

