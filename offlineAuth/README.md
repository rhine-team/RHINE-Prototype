 # Prototype Implementation of Rains Delegation Authentication Protocol. 

**Code in cyrill-k/trustflex directory is copied from https://github.com/cyrill-k/trustflex**

**Some Code in common/logclient.go is copied from https://github.com/cyrill-k/trustflex/trillian/tmain/main.go**

**Code to handle configs is copied from https://github.com/netsec-ethz/rains**

## Dependencies: 
Two packages need to be replaced, change 

```replace github.com/google/trillian => /home/netsec/go/src/github.com/cyrill-k/trillian```

```replace github.com/miekg/dns => /home/netsec/go/src/github.com/rhine-team/dns```

to your path in `go.mod`

Clone the repos from here: 

trillian: `github.com/cyrill-k/trillian`

miekg/dns: `github.com/rhine-team/dns`

## System Components: 
   - Child: Command line program for child zone authorities to renew their certificates. Sends ReNewDlg and KeyChangeDlg requests to a CA and adds them to the log. 
   - Parent: Command line program for a parent zone authority to obtain a certificate for a child zone. Parent creates NewDlg Requests using a CSR from one of its child zones and sends them to a CA. It also adds obtained Certificates to the log server.   
   - CA: Server receiving NewDlg requests from a parent zone and ReNewDlg/KeyChangeDlg requests from a child zone. It contacts the log-server to check for existing certificates. 
   - CheckerExtension: Checker Extension is the interface for parent and child zones to add certificates to the log. The log server must only accept new certificates from the checker extension.

## How to run 

### trustflex-docker 
trustflex-docker is a container cluster for the log server components. Rainsdeleg uses the map-server to receive information on existing certificates and the log-server  to add certificates. 
Repo can be found here: ``github.com/cyrill-k/trustflex-docker``

Make sure to add ``EXPOSE 8090`` and ``EXPOSE 8094`` to ``Go/Dockerfile`` so that the map-server and log-server can be accessed. Later the checkerExtension should be a container itself and the log-server should no longer be accessible from the outside. (dont expose 8090)

Run `docker-compose up` to start the log server components

Access the container: ``docker exec -i -t experiment bash``

Check out the `makefile` in `cyrill-k/trustflex` for log server administration.
Before using it for rainsdeleg  run
`make createlog` and `make createmap`

Update configs of rainsdeleg systems with `logid1 mapid1 logpk1.pem mapk1.pem`. They can be found in 
the confing folder of the trustflex-docker repo or in `/mnt/config/` in the container. 

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
../buld/child NewDlg Ed25519 testdata/keys/ethz.ch_Key.pem --out example/ --zone ethz.ch
../build/parent testdata/configs/ch_parentconfig.conf --NewDlg example/eth.ch_csr.pem
```


### Run Tests

`make test`

trustflex-docker needs to be running. Test configs are set to log-server address `172.18.0.3` and 
map-server address `172.18.0.5`. 

Check your container addresses: \
`docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' map-server` \
`docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' log-server`
