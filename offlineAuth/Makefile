BUILD_PATH=${PWD}/build/
	
all: clean zonemanager log ca aggregator
	
clean:
	rm -rf ${BUILD_PATH}
	mkdir ${BUILD_PATH}
	
zonemanager:
	go build -o ${BUILD_PATH}zoneManager cmd/zoneManager/run_zoneManager.go
	
log:
	go build -o ${BUILD_PATH}log cmd/log/run_Log.go

ca:
	go build -o ${BUILD_PATH}ca cmd/ca/run_CA.go

aggregator:
	go build -o ${BUILD_PATH}aggregator cmd/aggregator/run_Aggregator.go


.PHONY: all clean zonemanager log ca aggregator