# Benchmarking
This directory contains helpers and data for benchmarking.

## Some terminal commands to start components
../build/aggregator AddDTBatch  --pCertDir data/temp/parentcerts --config data/configs/configAgg2_1.json

../build/aggregator --config=data/configs/configAgg2_1.json

../build/aggregator --config=data/configs/configAgg2_2.json

../build/log --config=data/configs/configLog2_1.json

../build/log --config=data/configs/configLog2_2.json

../build/ca --config=data/configs/configCA.json


../build/zoneManager RunParentServer --config=data/configs/parentDummyConfig.json


../build/zoneManager RequestDeleg --config data/configs/childDummyConfig.json --output data/certs/delegResultCert.pem --zone 78RHxwinFb7Dhe0.ZN0aO15uHCufrJH.benchmark.ch --privkey data/temp/childrenkeys/78RHxwinFb7Dhe0.ZN0aO15uHCufrJH.benchmark.ch.pem


