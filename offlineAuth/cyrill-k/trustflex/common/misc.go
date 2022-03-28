// This file holds various functions
// used by different entities

package common

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"
)

var (
	DisableLogging bool
	EnableDebug    bool
)

func OpenOrCreate(filename string) (*os.File, error) {
	info, _ := os.Stat(filename)
	if info != nil && info.IsDir() {
		return nil, fmt.Errorf("Cannot create or open: '%s' is a directory", filename)
	}
	return os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
}

func Min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func LoadConfig(fileName string, config interface{}) {
	jsonFile, err := os.Open(fileName)
	LogError("Failed to open "+fileName+": %s", err)

	byteFile, err := ioutil.ReadAll(jsonFile)
	LogError("Failed to read "+fileName+": %s", err)

	LogError("Failed to close "+fileName+": %s", jsonFile.Close())

	err = json.Unmarshal(byteFile, &config)
	LogError("Failed to unmarshal json into struct: %s", err)

}

func SliceIncludes(slice []string, element string) bool {
	for _, s := range slice {
		if s == element {
			return true
		}
	}
	return false
}

func MapKeysSlice(ogMap map[string][]byte) []string {
	keys := make([]string, len(ogMap))
	idx := 0
	for key, _ := range ogMap {
		keys[idx] = key
		idx++
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})

	return keys
}

func AppendToByteSlice(data interface{}, id string, typ string, errMsg string) []byte {
	byteData, err := json.Marshal(data)
	LogError(errMsg, err)
	byteId := []byte(id)
	byteType := []byte(typ)
	var fields []byte
	fields = append(fields, byteData...)
	fields = append(fields, byteId...)
	fields = append(fields, byteType...)
	return fields
}

func AwaitSignal(function func()) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigs
	log.Printf("Signal received: %v", sig)
	function()
}

func LogError(msg string, err error) {
	if err != nil {
		log.Printf(msg, err)
	}
}

func Log(s string, args ...interface{}) {
	if !DisableLogging {
		log.Printf(s, args...)
	}
}

func Debug(s string, args ...interface{}) {
	if EnableDebug {
		log.Printf(s, args...)
	}
}

func StringSliceCompare(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, ae := range a {
		if ae != b[i] {
			return false
		}
	}
	return true
}

func GetAverages(m map[int64][]int64) (avg map[int64]float64) {
	avg = make(map[int64]float64)
	for k := range m {
		avg[k] = 0
		for _, x := range m[k] {
			avg[k] += float64(x)
		}
		avg[k] /= float64(len(m[k]))
	}
	return avg
}

func GobWriteMapIntSlice(f string, m map[int64][]int64) error {
	dataFile, err := os.Create(f)
	if err != nil {
		return err
	}
	defer dataFile.Close()

	dataDecoder := gob.NewEncoder(dataFile)
	err = dataDecoder.Encode(m)
	if err != nil {
		return err
	}

	return nil
}

func GobReadMapIntSlice(f string, m *map[int64][]int64) error {
	if _, err := os.Stat(f); os.IsNotExist(err) {
		*m = make(map[int64][]int64)
		return nil
	}
	dataFile, err := os.Open(f)
	if err != nil {
		return err
	}
	defer dataFile.Close()

	dataDecoder := gob.NewDecoder(dataFile)
	err = dataDecoder.Decode(m)
	if err != nil {
		return err
	}

	return nil
}

func GobWriteMapBool(f string, m map[string]bool) error {
	dataFile, err := os.Create(f)
	if err != nil {
		return err
	}
	defer dataFile.Close()

	dataDecoder := gob.NewEncoder(dataFile)
	err = dataDecoder.Encode(m)
	if err != nil {
		return err
	}

	return nil
}

func GobReadMapBool(f string, m *map[string]bool) error {
	if _, err := os.Stat(f); os.IsNotExist(err) {
		*m = make(map[string]bool)
		return nil
	}
	dataFile, err := os.Open(f)
	if err != nil {
		return err
	}
	defer dataFile.Close()

	dataDecoder := gob.NewDecoder(dataFile)
	err = dataDecoder.Decode(m)
	if err != nil {
		return err
	}

	return nil
}
