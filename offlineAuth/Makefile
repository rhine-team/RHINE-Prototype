BUILD_PATH=${PWD}/build/

all: clean child parent ca checker keymanager

clean:
	rm -rf ${BUILD_PATH}
	mkdir ${BUILD_PATH}

child:
	go build -o ${BUILD_PATH}child cmd/child/run_child.go

parent:
	go build -o ${BUILD_PATH}parent cmd/parent/run_parent.go

ca:
	go build -o ${BUILD_PATH}ca cmd/ca/run_ca.go

checker:
	go build -o ${BUILD_PATH}checker cmd/checkerExtension/run_checker.go

keymanager:
	go build -o ${BUILD_PATH}keyGen cmd/keyManager/keyGen.go
	go build -o ${BUILD_PATH}certGen cmd/keyManager/certGen.go


test:
	go test -v test/rainsdeleg_test.go -run TestFull

.PHONY: all clean child parent ca checker keymanager test