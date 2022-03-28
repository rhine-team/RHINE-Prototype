package rainsclientlog

import (
	"crypto/x509"
	"fmt"
	"github.com/rhine-team/RHINE-Prototype/cyrill-k/trustflex/common"
	"github.com/rhine-team/RHINE-Prototype/cyrill-k/trustflex/trillian/mapper"
	"github.com/rhine-team/RHINE-Prototype/cyrill-k/trustflex/trillian/tclient"
	"log"
	"os"
)

var maxReceiveMessageSize = 1073741824
var First = true

func QueryMapServerZoneInfo(zone string, mapID int64, LogAddr string, LogPkeyPath string) ([][]x509.Certificate, error) {
	mapClient := tclient.NewMapClient(LogAddr, LogPkeyPath, maxReceiveMessageSize)
	defer mapClient.Close()

	proofs, err := mapClient.GetProofForDomains(mapID, mapClient.GetMapPK(), []string{zone})
	common.LogError("Couldn't retrieve proofs for all domains: %s", err)
	if err != nil {
		return nil, err
	}

	proof := proofs[0]

	if proof.GetDomain() == zone {
		err := proof.Validate(mapID, mapClient.GetMapPK(), common.DefaultTreeNonce, zone)
		if err != nil {
			log.Printf("Entry %d (%s): Validate failed: %s", 0, proof.GetDomain(), err)
			return nil, err
		}
		log.Printf("Entry %d (%s): %s", 0, proof.GetDomain(), proof.ToString())
	} else {
		log.Printf("Proof for wrong zone: %s, expected: %s", proof.GetDomain(), zone)
		return nil, err
	}
	certs := proof.GetUnrevokedCertificates(zone)
	return certs, nil

}

func AddToLogServer(cert *x509.Certificate, logID int64, LogAddress string, LogPkeyPath string) {
	logClient := tclient.NewLogClient(LogAddress, LogPkeyPath, maxReceiveMessageSize)
	defer logClient.Close()
	logClient.LogCert(cert, logID)
}

func Mapping(MapPkeyPath string, MapID int64, MapAddress string, LogPkeyPath string, LogID int64, LogAddress string) error {
	log.Printf("mapping %s", MapPkeyPath)
	mper, err := mapper.NewMapper(MapAddress, MapPkeyPath, "logdata/valid.gob", "logdata/invalid.gob", "logdata/dropped.csv", maxReceiveMessageSize)
	if err != nil {
		common.LogError("Couldn't create mapper: %s", err)
		return err
	}
	defer mper.Close()

	lastIdx := readLastIdx()
	lastIdx, err = mper.PerformMapping(LogAddress, LogPkeyPath, LogID, MapID, lastIdx)
	common.LogError("Mapping failed: %s", err)
	return err
}

func RevokeCert(cert *x509.Certificate, MapPkeyPath string, MapID int64, MapAddress string) {
	mapClient := tclient.NewMapClient(MapAddress, MapPkeyPath, maxReceiveMessageSize)
	defer mapClient.Close()
	encodedMapEntries, err := mapClient.GetValues(MapID, mapClient.GetMapPK(), []string{cert.DNSNames[0]}, true, true)
	common.LogError("Get Values failed: %s", err)
	fmt.Println(encodedMapEntries)

	setmap := map[string]tclient.EncodedMapEntry{}

	for _, entry := range encodedMapEntries {
		var existing tclient.MapEntryType
		err = existing.UnmarshalBinary(entry.LeafValue)

		fmt.Println("Get Map Entry to Revoke Cert: ", existing.ToString())
		revocations := existing.GetRevocations()
		for _, rev := range revocations {
			fmt.Println(string(rev.GetMessage()), rev.GetRevokedSerialNumber())
		}
		certificates := existing.GetCertificates()

		var chainleafs []x509.Certificate
		for _, chain := range certificates {
			chainleafs = append(chainleafs, chain[0])
		}

		var certToRevoke *x509.Certificate
		for _, logcert := range chainleafs {
			if logcert.Equal(cert) {
				certToRevoke = &logcert
			}
		}

		if certToRevoke == nil {
			fmt.Println("WARNING: Cert to revoke not found in Log")
		} else {
			existing.Revocations = append(existing.Revocations, tclient.RevocationMessageType{
				SerialNumber: *certToRevoke.SerialNumber,
				Message:      []byte("Revoked"),
			})
			leafValue, err := existing.MarshalBinary()
			if err != nil {
				common.LogError("Failed to Marshal Binary: %s", err)
			} else {
				entry.LeafValue = leafValue
				setmap[cert.DNSNames[0]] = *entry
				break
			}

		}
	}

	err = mapClient.SetValues(MapID, mapClient.GetMapPK(), setmap, true)
	common.LogError("Failed to set new values: %s", err)

}

func readLastIdx() int64 {
	var lastIdx int64
	lastIdx = 0
	if !First {
		file, _ := os.Open("trillian/lastIdx")
		// common.LogError("Failed to open lastIdx file: %s", err)
		defer file.Close()

		_, _ = fmt.Fscanf(file, "%d", &lastIdx)
		// common.LogError("Failed reading lastIdx: %s", err)
	} else {
		//First = false  // TODO investigate why sometimes not updating mapping when this is used
	}
	return lastIdx
}
