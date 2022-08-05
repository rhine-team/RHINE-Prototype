# Test with docker-compose

## Build local images

### Build nameserver image
Go to folder `onlineProtocol/nameserver/coredns`
If you are using OS other than linux, add `GOOS=linux` before `go build` command of `onlineProtocol/nameserver/coredns/Makefile` like this:
```
	GOOS=linux CGO_ENABLED=$(CGO_ENABLED) $(SYSTEM) go build $(BUILDOPTS) -ldflags="-s -w -X github.com/coredns/coredns/coremain.GitCommit=$(GITCOMMIT)" -o $(BINARY)

```

Then build the source code
```
make
```

Build the docker image
```
docker build -t coredns .
```

### Build resolver image
Go to folder `onlineProtocol/resolver/sdns`

Build the source code
```
make
```

Build the docker image
```
docker build -t sdns .
```

## Start resolver and nameservers
Run `docker compose up -d`

It will start nameservers: root, `com.` , `rhine-test.com.`  and recursive resolver in a single network.

## Send query using rdig
After the docker services are on, use `rdig` to query the resolver, the resolver is listening on port 10003 of localhost.

For the current test servers, the CA certificate is stored in `onlineProtocol/client/rdig/testdata/certificate/CACert.pem`, specify the CA certificate with `-cert` flag while doing the query, also enable rhine E2E validation with `-rhine` flag.
for e.g. :
```
./rdig -port 10003 -rhine -cert=./testdata/certificate/CACert.pem @localhost www1.com.
```

## Configure Zones
Zone files for test nameserves can be configured in `onlineProtocol/testdata/nameserver/zones`

Corefiles for plugin used in each zone can be configured in `onlineProtocol/testdata/nameserver`

If more test servers are needed, please also change the `docker-compose.yml` correspondingly.

## Configure Resolver
Configure the resolver by changing `onlineProtocol/testdata/resolver/config.yml`

Test CA certificates are stored in `onlineProtocol/testdata/resolver/certificates`

