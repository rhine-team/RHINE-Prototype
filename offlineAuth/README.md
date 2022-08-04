# RHINE Offline Authentication Protocol

This directory contains a prototype implementation of the RHINE offline autentication protocol

## Architecture
![RHINEArchitecture](docs/RHINE_offlineAuth_Architecture.png?raw=true "RHINE_Architecture")

The RHINE offline authentication protocol makes use of four components: Aggregators, Loggers, a Certificate Authority and a Zone Manager. The latter provides functionality to zones to request a delegation as well as for parents to run a parent server allowing its children to be delegated to. 
Loggers log certificates by using Google's Certificate Transperancy as a backend, they also serve data related to RHINE's Delegation Transperancy, for which the Aggregators are responsible for. 
gRPC is used to connect all running components and data is marshalled for the gRPC calls using CBOR. 


## How to conduct a test run
This section explains how to conduct a toy example of the offline authentication prototype using one logger and one aggregator. Note that key generation can be skipped if one wants to use the provided example keys.

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

### Setup Certificate Transperancy infrastructure
As a first step, we have to generate a key pair for our logger, which can be done using the provided key manager:

``cd cmd/keyManager``
``go run keyGen.go RSA ../log/data/Logger1.pem --pubkey ``


Note that a RSA key has to be used for this step, as CT does not currently support Ed25519. We use the generated key for the Logger server as well as for the CT personality, so copy the printed DER hex string of the key for later use. To setup the CT infrastructure, we start with Trillian (this can be done from where ever):
```bash
git clone https://github.com/google/trillian.git
cd trillian

go build ./...
```
Docker is used to deploy trillian for this example, following [this](https://github.com/google/trillian/tree/master/examples/deployment) documentation:

```bash
# Set a random password
export MYSQL_ROOT_PASSWORD="$(openssl rand -hex 16)"

# Bring up services defined in this compose file.  This includes:
# - local MySQL database
# - container to initialize the database
# - the trillian server
docker-compose -f examples/deployment/docker-compose.yml up
```

A test MySQL should have been created. Check the state of the docker containers with ``docker ps``. The data base container should be available at port 3306 and the log server at 8091. Verify the latter using: 
``curl localhost:8091/metrics``

As a next step we create a tree which will log our certificates by using the createtree tool:

```bash
go build github.com/google/trillian/cmd/createtree/
./createtree --admin_server=localhost:8090
```

It is important to remember the ID of the created tree for the next step, which is starting the CT personality:

```bash
git clone https://github.com/google/certificate-transparency-go.git
```

For that, we need to provide a configuration file which has the following format:

```
config {
    log_id: [CREATED TREE ID]
    prefix: "RHINE"
    roots_pem_file: [PATH TO CA CERTIFICATE]
    private_key: {
        [type.googleapis.com/keyspb.PrivateKey] {
            der: "[DER HEX STRING]"
        }
    }
    max_merge_delay_sec: 86400
    expected_merge_delay_sec: 120
}

```
In "cmd/log/data/configs" you can also find an example config for the personality. Paste in the log id from the createtree tool, the path to our CA certificate, and the DER hex string representing the logger private key, which will be used to sign Signed Certificate Timestamps. Now start the personality:
```bash
# From the certificate-transperancy repo
cd trillian/ctfe/ct_server
go run main.go --log_config=[CTConfigPath] --log_rpc_server=127.0.0.1:8090 --http_endpoint=localhost:6966  --logtostderr
```

Verify that it is working by visiting [http://localhost:6966/RHINE/ct/v1/get-sth](http://localhost:6966/RHINE/ct/v1/get-sth), which should provide the signed hash for our created tree.

### Setup and start the Aggregator
An example config for the aggregator can be found below and at "cmd/aggregator/configs". "KeyValueDBDirectory" indicates the path where the data base storing our Delegation Transperancy will be located. The Aggregator will initialize it on its own.
```json
{
    "PrivateKeyAlgorithm": "Ed25519",
    "PrivateKeyPath": "data/Agg1.pem",
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

### Setup and start the Logger
To start the Logger, we provide a configuration file with the following format. Fill in the needed values if not using example key data. An example of a config can also be found under "cmd/log/configs". 

```json
{
    "PrivateKeyAlgorithm": "RSA",
    "PrivateKeyPath": "data/Log1_RSA.pem",
    "ServerAddress" : "localhost:50016",
    "RootCertsPath" : "data/roots/",
    
    "LogsName" :       ["localhost:50016"],
    "LogsPubKeyPaths" :    ["data/pubkeys/logs/Log1_RSA_pub.pem"],
    
    "AggregatorName" :  ["localhost:50050"],
    "AggPubKeyPaths"  : ["data/pubkeys/aggregators/Agg1_pub.pem"],
    
    "CAName" : "localhost:10000",
   	"CAServerAddr" : "localhost:10000",
    "CAPubKeyPath" : "data/pubkeys/ca/CA_pub.pem",
    
    "CTAddress": "localhost:6966",
    "CTPrefix": "RHINE",
    
    "KeyValueDBDirectory" : "data/badger_database"
}

```

Important: The logger needs to be run AFTER the aggregator, as it will request some information from it at start-up. To run the logger:

```bash
# From the offlineAuth directory
cd cmd/log
go run run_Log.go --config=[PathToConfigFile]

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
If not using the example data, key paths, aggregator addresses and public keys, etc. need to be set correctly with the previously generated keying material. Note that for this and our other components, the directory described by RootCertsPath, should contain our CA's certificate, indicating that we trust it as a signing authority. To run the CA:
```bash
# From the offlineAuth directory
cd cmd/ca
go run run_CA.go --config=[PathToConfigFile]

```


### Setup and start the parent server
The parent server is needed to approve of the initial delegation. Again, a configuration file can be found at "cmd/zoneManager/configs".
Pay attention to the "ChildrenKeyDirectoryPath" json key, it indicates the directory where the parent saves the public keys of its children to be delegated.
```bash
# From the offlineAuth directory
cd cmd/zoneManager
go run run_zoneManager.go RunParentServer --config=[PathToConfigFile]

```

### Conduct the test run
As we know that all components are running, we can run the initial delegation from the view of a child zone. 
First we again create a key pair using the key manager. Next, we place the created public key in the "ChildrenKeyDirectoryPath" directory of the parent server. It is important that the public key is renamed to [ChildZoneName]_pub.pem (example.ethz.ch_pub.pem for example), or the parent server will not find it. 
This represents the out-of-band authenticated key exchange, which is the first step of our protocol. 

Again we have to use a config to describe the RHINE eco-system, an example of which is provided here: "cmd/zoneManager/configs". We run the initial delegation protocol the following way:

```bash
# From the offlineAuth directory
cd cmd/zoneManager
go run run_zoneManager.go RequestDeleg --config=[PathToConfigFile] --zone=[ZoneName] --ind

```

Other flags can be used to for example provide the parent server address, if not specified in the config file. The zone flag should be set to the child zone name, for example: --zone=example.ethz.ch

You should see a string representation of the received certificate in the terminal and a stored pem encoded certficated in the file system as result from the initial delegation.

### Clearing the DT data bases
If you want to run the toy example again. The new delegation needs to be cleared from the data bases in the aggregator and logger. Do this following way:

```bash
# From the offlineAuth directory
cd cmd/log
go run run_Log.go WipeDB --config=[PathToConfigFile]
cd ../aggregator
go run run_Aggregator.go WipeDB --config=[PathToConfigFile]

```

