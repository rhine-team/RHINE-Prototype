# RHINE-Prototype

The RHINE sytem architecture can be devided into two parts: offline authentication and related tools like zone management and an online part for name resolution (resolver, nameserver, client). Below both are described and a toy example is provided.


# RHINE Offline Authentication Protocol

## Architecture
![RHINEArchitecture](docs/RHINE_offlineAuth_ArchitectureNew.png?raw=true "RHINE_Architecture")

The RHINE offline authentication protocol makes use of three components: Loggers, a Certificate Authority and a Zone Manager. The latter provides functionality to zones to request a delegation as well as for parents to run a parent server allowing its children to be delegated to. 
Loggers keep track of RHINE's Delegation Transperancy, serve data related to it for use during delagation or name server setup and take part in the secure delegation setup themselves. 
gRPC is used to connect all running components and data is marshalled for the gRPC calls using CBOR. 

## Code structure
- *internal/cbor* contains Marshalling/Unmarshalling wrappers for gRPC to use
- *cmd* contains the command line interfaces for the different parts of the protocol, for example to start a CA or run a parent server as well as directories for test data and data bases
- *internal/components* contains 1. the service and message specification for our gRPC servers and 2. the servers themselves
- *internal/keyManager* contains some functionality related to generating keys and test certificates
- *pkg/rhine* is a go package containing data structures related to the offlineAuth protocol as well as methods used in protocol logic

The used  merkletree implementation is a  changed version of ["github.com/cbergoon/merkletree"](https://github.com/cbergoon/merkletree). We use ["github.com/fxamacker/cbor/v2"](https://github.com/fxamacker/cbor) as our CBOR implementation. Some parts of the code are reused from the old offlineAuth implementation by ----- like some util and modified keyManager functions.


## How to conduct a test run
This section explains how to conduct a toy example of the offline authentication prototype using one logger. The benchmark directory contains some configs and keying material with multiple numbers of loggers that can be used instead.


### Create keys and certificates
Each of our component needs a key pair, using either RSA+SHA256 or Ed25519 for signing. Create key pairs for the logger, aggregator, ca and parent using the keyManager:

```bash
cd cmd/keyManager
go run keyGen.go Ed25519 [KeyOutputPath] --pubkey 
```

Instead of creating you own keys, one can also use the provided example keys with the example configuration files.
We have to also create a self signed certificate for the CA which will serve as a trust root:

```bash
go run certGen.go Ed25519 [PrivateKeyPath] [CertificatePath]
```

The parent will need to provide a certificate, which we create for testing purposes:

```bash
go run certGenByCA.go Ed25519 [PrivateKeyPath] [CAKeyPath] [CACertPath] [CertificatePath] [NAME]
```

[NAME] should be the parent zone name. Again, the provided example files can be used instead(for a child called example.ethz.ch and a parent ethz.ch)


### Setup and start the Loggers
An example config for the aggregator can be found below and at "cmd/aggregator/configs". "KeyValueDBDirectory" indicates the path where the data base storing our Delegation Transperancy will be located. The Aggregator will initialize it on its own.
```json
{
    "PrivateKeyAlgorithm": "Ed25519",
    "PrivateKeyPath": "data/Log1.pem",
    "ServerAddress" : "localhost:50050",
    "RootCertsPath" : "data/roots/",
    
    "LogsName" :       ["localhost:50016"],
    "LogsPubKeyPaths" :    ["data/pubkeys/logs/Log1_RSA_pub.pem"],
    
    "AggregatorName" :  ["localhost:50050"],
    "AggPubKeyPaths"  : ["data/pubkeys/aggregators/Agg1_pub.pem"],
    
    "CAName" : "localhost:10000",
    "CAServerAddr" : "localhost:10000",
    "CAPubKeyPath" : "data/pubkeys/ca/CA_pub.pem",
    
    "KeyValueDBDirectory" : "data/badger_database"
}

```

Note that we need some existing DT data structures for our test run, else the components will not accept our new delegation. Create these the following way:
```bash
# From the offlineAuth directory
cd cmd/aggregator
go run run_Aggregator.go AddTestDT --config=[PathToConfigFile] --parent=[ExampleParentZone] --certPath=[PathToTheParentsCertificate]

```

It is important that the --parent flag matches the name that was used when creating the parent certificate in the first step, so for example: ethz.ch
Now we can run our aggregator:


```bash
# From the offlineAuth directory
cd cmd/aggregator
go run run_Aggregator.go --config=[PathToConfigFile]

```


### Setup and start the CA
To run our CA we provide a configuration file that provides information regarding our architecture. An example of a valid config file can be seen below.
```json
{
    "PrivateKeyAlgorithm": "Ed25519",
    "PrivateKeyPath": "data/CAKey.pem",
    "CertificatePath": "data/CACert.pem",
    "ServerAddress" : "localhost:10000",
    "RootCertsPath" : "data/roots/",
    
    "LogsName" :       ["localhost:50016"],
    "LogsPubKeyPaths" :    ["data/pubkeys/logs/Log1_RSA_pub.pem"],
    
    "AggregatorName" :  ["localhost:50050"],
    "AggPubKeyPaths"  : ["data/pubkeys/aggregators/Agg1_pub.pem"]
}
```
If not using the example data, key paths, loggers addresses and public keys, etc. need to be set correctly with the previously generated keying material. Note that for this and our other components, the directory described by RootCertsPath, should contain our CA's certificate, indicating that we trust it as a signing authority. To run the CA:
```bash
# From the offlineAuth directory
cd cmd/ca
go run run_CA.go --config=[PathToConfigFile]

```


### Setup and start the parent server
The parent server is needed to approve of the initial delegation. A configuration file can be found at "cmd/zoneManager/configs". Pay attention to the *ParentDataBaseDirectory* as it needs to be a path to the parent data base containing parent certificates and children public keys, which need to be created in the next step.


```bash
# From the offlineAuth directory
cd cmd/zoneManager
go run run_zoneManager.go RunParentServer --config=[PathToConfigFile]

```

### Conduct the test run
As we know that all components are running, we can run the initial delegation from the view of a child zone. 
~~First we again create a key pair using the key manager. Next, we place the created public key in the "ChildrenKeyDirectoryPath" directory of the parent server. It is important that the public key is renamed to [ChildZoneName]_pub.pem (example.ethz.ch_pub.pem for example), or the parent server will not find it. ~~
To create children key-pairs, parent certificate(s) and the required data base the script in *benchmark/createBenchmarkData.go* can be used.
This represents the out-of-band authenticated key exchange, which is the first step of our protocol. 

The keys created with this script are named after their child zones so one can be picked for the toy example. Again we have to use a config to describe the RHINE eco-system, an example of which is provided here: "cmd/zoneManager/configs". We run the initial delegation protocol the following way:

```bash
# From the offlineAuth directory
cd cmd/zoneManager
go run run_zoneManager.go RequestDeleg --config=[PathToConfigFile] --zone=[ZoneName] --ind

```

Other flags can be used to for example provide the parent server address, if not specified in the config file. The zone flag should be set to the child zone name, for example: --zone=example.ethz.ch

You should see a string representation of the received certificate in the terminal and a stored pem encoded certficated in the file system as result from the initial delegation.

### Clearing the DT data bases
If you want to run the toy example again. The new delegation needs to be cleared from the data bases in the  logger. Do this following way:

```bash
# From the offlineAuth directory
cd ../aggregator
go run run_Aggregator.go WipeDB --config=[PathToConfigFile]

```

# Test Online Resolution with docker-compose

## Build local images

### Build nameserver image
Go to folder `internal/rserver/coredns`
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
Go to folder `internal/rresolv/sdns`

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

For the current test servers, the CA certificate is stored in `cmdt/rdig/testdata/certificate/CACert.pem`, specify the CA certificate with `-cert` flag while doing the query, also enable rhine E2E validation with `-rhine` flag.
for e.g. :
```
./rdig -port 10003 -rhine -cert=./testdata/certificate/CACert.pem @localhost www1.com.
```

## Configure Zones
Zone files for test nameserves can be configured in `examples/testdata/nameserver/zones`

Corefiles for plugin used in each zone can be configured in `examples/testdata/nameserver`

If more test servers are needed, please also change the `docker-compose.yml` correspondingly.

## Configure Resolver
Configure the resolver by changing `examples/testdata/resolver/config.yml`

Test CA certificates are stored in `examples/testdata/resolver/certificates`

