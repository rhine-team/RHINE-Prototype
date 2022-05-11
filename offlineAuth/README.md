 # RAINS Offline Authentication Protocols

 This is a prototype implementation of the [offline protocols](https://github.com/netsys-lab/scion-rains/tree/master/docs/auth-arch) of RAINS new authentication architecture.


## Dependencies: 

Libraries:

- Modified Trillian: `https://github.com/cyrill-k/trillian`

- Modified miekg/dns: `https://github.com/robinburkhard/dns`


Notes:

- Code in `cyrill-k/trustflex` directory is copied from `https://github.com/cyrill-k/fpki`

## How to run (see a step-by-step setup below)

### fpki-docker 
fpki-docker is a container cluster for the log server components. Rainsdeleg uses the map-server to receive information on existing certificates and the log-server  to add certificates. 
Repo can be found here: ``https://github.com/cyrill-k/fpki-docker``

Make sure to add ``EXPOSE 8090`` and ``EXPOSE 8094`` to ``Go/Dockerfile`` so that the map-server and log-server can be accessed. Later the checkerExtension should be a container itself and the log-server should no longer be accessible from the outside. (dont expose 8090)

Run `docker-compose up` to start the log server components

Access the container: ``docker exec -i -t experiment bash``

Check out the `makefile` in `cyrill-k/fpki` for log server administration.
Before using it for rainsdeleg  run
`make createmap` and `make createtree` and `make map_initial`

Update configs of rainsdeleg systems with `logid1 mapid1 logpk1.pem mapk1.pem`. They can be found in 
the confing folder of the fpki-docker repo or in `/mnt/config/` in the container. 

### Makefile

run ``make all`` to create `ca` `checker` `parent` `child` `keyGen` `certGen` binaries in `/build`.  

### CA and CheckerExtension 

Run `./ca [ConfigPath]` and `./checker [ConfigPath]`. 
Example configs can be found in `testing/testdata/configs/`

More information about the components and their config can be found in `ca/README.md` and `checkerExtension/README.md`

### Parent Zone Manager

Handles NewDlg requests for a given CSR \
`./parent [ParentConfigPath] --NewDlg PathToCSR`

### Child Zone Manager 
Handles Creating CSRs for NewDlg or ReNewDlg and KeyChangeDlg requests \
`./child NewDlg [KeyType] [PathToPrivateKey] --zone DNSZone`\
`./child ReNewDlg [KeyType] [PathToPrivateKey] [PathToCertificate]`
 

### KeyGen 

Use `./keyGen.go` and `./certGen.go` to generate keys and self signed CA certificates for testing
### Examples 

Run CA and Checker: 
```
cd testing 
../build/ca testdata/configs/caconfig.conf
../build/checker testdata/configs/checkerconfig.conf
```
Create NewDlg Request for `ethz.ch` using parent for zone for `ch`
```
../build/child NewDlg Ed25519 testdata/keys/ethz.ch_Key.pem --out example/ --zone ethz.ch
../build/parent testdata/configs/ch_parentconfig.conf --NewDlg example/eth.ch_csr.pem
```


### Run Tests

`make test`

fpki-docker needs to be running. Test configs are set to log-server address `172.18.0.3` and 
map-server address `172.18.0.5`. 

Check your container addresses: \
`docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' map-server` \
`docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' log-server`


## Setup step by step (toy example) 

### Step 1: setup repo and dependencies 

Clone this repo. Clone `github.com/cyrill-k/trillian` and `github.com/robinburkhard/dns`.

In the `go.mod` of this repo, change

```replace github.com/google/trillian => [path to the just cloned Trillian repo]```

```replace github.com/miekg/dns => [path to the just cloned miekg/dns repo]```


### Step 2: setup F-PKI environment 

clone ``github.com/cyrill-k/fpki-docker``

add ``EXPOSE 8090`` and ``EXPOSE 8094`` to ``Go/Dockerfile``

Run `docker-compose up` in repo folder to start

Access the container: ``docker exec -i -t experiment bash`` and run `mkdir data` and `make createmap` and `make createtree` and `make map_initial`

read out `logid1 mapid1 logpk1.pem mapk1.pem` in `/mnt/config/` 

### Step 3: update and create configs for your F-PKI setup 

change at least: 

```go
MAP_PK_PATH     = "testdata/mappk1.pem"
LOG_PK_PATH     = "testdata/logpk1.pem"
MAP_ID          = 3213023363744691885
LOG_ID          = 8493809986858120401
```

in `offlineAuth/test/rainsdeleg_test.go` to fit your f-pki setup. Also change the keys `testdata/logpk1.pem` and `testdata/mapk1.pem`.

Then run the `TestCreateDemoFiles2` (run `go test -run TestCreateDemoFiles2` in `/offlineauth/test/`) function to create necessary configs and keys to run a manual toy example. Alternatively use `TestFull` function to test automatically. 

Troubleshooting: On Map-Address (or Log-Address) error, use docker inspect command above to check if the map-server is running on `172.18.0.5` as expected. If not, change addresses in `rainsdeleg_test.go`

### Step 4: run toy example with demo files 

run `make` to create the binaries in `/build`

check if `testdata/logpk1.pem` and `testdata/mapk1.pem` match your f-pki setup

check if `LogID` and `MapID` values in `demo/checker.conf` and  `demo/ca.conf` match your f-pki setup

run ca: 

``cd test ``

``../build/ca demo/ca.conf``


run checker: 

 ``cd test ``
 
 ``../build/checker demo/checker.conf ``


child generate key and csr:

 ``../build/keyGen Ed25519 demo/ethz.ch.rains.key ``
 
 ``../build/child NewDlg Ed25519 demo/ethz.ch.rains.key --zone ethz.ch.rains --out demo ``
 
parse: 
``openssl req -text -noout -in demo/ethz.ch.rains_Csr.pem``


parent run newdlg :


 `` ../build/parent demo/ch.conf --NewDlg demo/ethz.ch.rains_Csr.pem ``

parse: 

 ``openssl x509 -text -noout -in demo/ch.cert `` 
 
 ``openssl x509 -text -noout -in demo/ethz.ch.rains_Cert.pem ``





