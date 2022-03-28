// This file holds Mapper-related code.
// The Mapper is responsible for mapping
// EECerts from the Log to the Map.
// The current implementation does not use
// this anymore, since the BFT already
// add the certificates to both the Map and the Log.

package mapper

import (
	"bufio"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/golang/protobuf/ptypes"
	ct "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/client/rpcflags"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/crypto/sigpb"
	"github.com/rhine-team/RHINE-Prototype/cyrill-k/trustflex/common"
	"github.com/rhine-team/RHINE-Prototype/cyrill-k/trustflex/trillian/tclient"
	"google.golang.org/grpc"
	"log"
	"os"
	"strings"
	"time"
)

type TrillianMapper interface {
	PerformMappingFromCTLog(ctLogAddress string, mapID int64, lastIdx int64, endIdx int64, batchSize int64) (int64, error)
	PerformMapping(logAddress string, logPk string, logID, mapID int64, lastIdx int64) (int64, error)
	PerformMappingFromProofs(proofs []tclient.Proof, mapID int64, batchSize int64) error
	ValidDomains() map[string]bool
	InvalidDomains() map[string]bool
	Close()
}

type trillianMapper struct {
	MapClient                            tclient.MapClient
	ValidDomainsFile, InvalidDomainsFile string
	validDomains, invalidDomains         map[string]bool
	DroppedLogEntryWriter                *common.DroppedLogEntryWriter
	maxReceiveMessageSize                int
}

func NewMapper(mapAddress, mapPk string, validDomainsFile, invalidDomainsFile string, droppedLogEntryFile string, maxReceiveMessageSize int) (TrillianMapper, error) {
	mapClient := tclient.NewMapClient(mapAddress, mapPk, maxReceiveMessageSize)

	f, err := common.OpenOrCreate(droppedLogEntryFile)
	if err != nil {
		return nil, fmt.Errorf("Can't open dropped log entry file: %s", err)
	}

	mapper := trillianMapper{MapClient: mapClient, ValidDomainsFile: validDomainsFile, InvalidDomainsFile: invalidDomainsFile, DroppedLogEntryWriter: common.NewDroppedLogEntryWriter(bufio.NewWriter(f)), maxReceiveMessageSize: maxReceiveMessageSize}
	err = mapper.readDomainsFromFile()
	if err != nil {
		return nil, fmt.Errorf("Error reading domains from file (%s,%s): %s", mapper.ValidDomainsFile, mapper.InvalidDomainsFile, err)
	}

	return &mapper, nil
}

type recursiveMapEntry struct {
	mapEntry   *tclient.MapEntryType
	subdomains map[string]*recursiveMapEntry
}

func (tm *trillianMapper) ValidDomains() map[string]bool {
	return tm.validDomains
}

func (tm *trillianMapper) InvalidDomains() map[string]bool {
	return tm.invalidDomains
}

func (tm *trillianMapper) readDomainsFromFile() error {
	if err := common.GobReadMapBool(tm.ValidDomainsFile, &tm.validDomains); err != nil {
		return err
	}
	if err := common.GobReadMapBool(tm.InvalidDomainsFile, &tm.invalidDomains); err != nil {
		return err
	}
	return nil
}

func (tm *trillianMapper) writeDomainsToFile() error {
	if err := common.GobWriteMapBool(tm.ValidDomainsFile, tm.validDomains); err != nil {
		return err
	}
	if err := common.GobWriteMapBool(tm.InvalidDomainsFile, tm.invalidDomains); err != nil {
		return err
	}
	return nil
}

func (tm *trillianMapper) getBatchEntries(ctClient *ctclient.LogClient, ctx context.Context, lastIdx int64, batchSize int64) (logEntries []ct.LogEntry, dropped []common.DroppedLogEntry) {
	var err error
	logEntries, err = ctClient.GetEntries(ctx, lastIdx, lastIdx+batchSize-1)
	if err == nil {
		// for i := 0; i < len(logEntries); i++ {
		// 	logEntryIndices = append(logEntryIndices, int64(lastIdx+i))
		// }
	} else {
		for i := int64(0); i < batchSize; i++ {
			singleLogEntry, err := ctClient.GetEntries(ctx, lastIdx+i, lastIdx+i)
			if err != nil {
				dropped = append(dropped, common.DroppedLogEntry{CtLogIndex: lastIdx + i, Error: err})
			} else {
				logEntries = append(logEntries, singleLogEntry[0])
				// logEntryIndices = append(logEntryIndices, lastIdx+i)
			}
		}
	}
	return
}

func (tm *trillianMapper) PerformMappingFromCTLog(ctLogAddress string, mapID int64, lastIdx int64, endIdx int64, batchSize int64) (int64, error) {
	ctClient, err := ctclient.New(ctLogAddress, nil, jsonclient.Options{})
	if err != nil {
		return lastIdx, fmt.Errorf("Failed to create CT client: %v", err)
	}

	// log write domains to disk
	defer func() {
		err := tm.writeDomainsToFile()
		if err != nil {
			log.Printf("Error writing domains from file (%s,%s): %s", tm.ValidDomainsFile, tm.InvalidDomainsFile, err)
		}
	}()

	ctx := context.Background()
	for {
		logEntries, batchDropped := tm.getBatchEntries(ctClient, ctx, lastIdx, batchSize)
		for _, d := range batchDropped {
			tm.DroppedLogEntryWriter.Write(&d)
		}
		// nEntries := batchSize
		// // Get the entries from the log:
		// logEntries, err := ctClient.GetEntries(ctx, lastIdx, common.Min(lastIdx+batchSize, endIdx))
		// if err != nil {
		// 	return lastIdx, dropped, fmt.Errorf("Failed to retrieve entries from CT log: %s", err)
		// }
		// if len(logEntries) == 0 {
		// 	return lastIdx, dropped, fmt.Errorf("No entries from log")
		// }
		common.Log("Retrieved [%d, %d] from %s; Failed %d", lastIdx, lastIdx+batchSize, ctLogAddress, len(batchDropped))

		var certs [][]x509.Certificate
		for _, entry := range logEntries {
			if entry.Leaf.LeafType != ct.TimestampedEntryLeafType {
				tm.DroppedLogEntryWriter.Write(&common.DroppedLogEntry{
					CtLogIndex: entry.Index,
					Error:      fmt.Errorf("Skipping unknown entry type %v at %d", entry.Leaf.LeafType, entry.Index)})
				continue
			}
			switch entry.Leaf.TimestampedEntry.EntryType {
			case ct.X509LogEntryType:
				cert, err := x509.ParseCertificate(entry.Leaf.TimestampedEntry.X509Entry.Data)
				if err != nil {
					tm.DroppedLogEntryWriter.Write(&common.DroppedLogEntry{
						CtLogIndex: entry.Index,
						Error:      fmt.Errorf("Can't parse certificate at index %d: %s", entry.Index, err)})
					continue
				}
				chainWithoutRootCert := []x509.Certificate{*cert}
				for i, asn1Cert := range entry.Chain {
					if i+1 < len(entry.Chain) {
						//don't store root certificate
						chainCert, err := x509.ParseCertificate(asn1Cert.Data)
						if err != nil {
							tm.DroppedLogEntryWriter.Write(&common.DroppedLogEntry{
								CtLogIndex: entry.Index,
								Error:      fmt.Errorf("Failed to parse certificate chain at %d for %s: %s", i, common.X509CertToString(cert), err)})
							break
						}
						chainWithoutRootCert = append(chainWithoutRootCert, *chainCert)
					}
				}
				if len(entry.Chain) == len(chainWithoutRootCert) {
					// only add certificate if the chain could be parsed
					certs = append(certs, chainWithoutRootCert)
				}
				// cert, err := x509.ParseCertificate(entry.Leaf.TimestampedEntry.X509Entry.Data)
				// if err != nil {
				// 	glog.Warningf("Can't parse cert at index %d, continuing anyway because this is a toy", entry.Index)
				// 	continue
				// }
				// updateDomainMap(domains, *cert, entry.Index, false)
			case ct.PrecertLogEntryType:
				tm.DroppedLogEntryWriter.Write(&common.DroppedLogEntry{
					CtLogIndex: entry.Index,
					Error:      fmt.Errorf("Ignoring precertificate")})
				// common.Log("Ignoring precertificate")
				// precert, err := x509.ParseTBSCertificate(entry.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate)
				// if err != nil {
				// 	glog.Warningf("Can't parse precert at index %d, continuing anyway because this is a toy", entry.Index)
				// 	continue
				// }
				// updateDomainMap(domains, *precert, entry.Index, true)
			default:
				tm.DroppedLogEntryWriter.Write(&common.DroppedLogEntry{
					CtLogIndex: entry.Index,
					Error:      fmt.Errorf("Ignoring unknown logentry type at index %d", entry.Index)})
			}
		}

		newLastIdx, err := tm.performMapping(certs, mapID, lastIdx, lastIdx+int64(len(logEntries)+len(batchDropped)), true)
		if err != nil {
			return lastIdx, err
		}
		lastIdx = newLastIdx
		if newLastIdx >= endIdx {
			common.Log("Finished mapping at %d", lastIdx)
			return lastIdx, nil
		}
	}
	return lastIdx, nil
}

// Map Log content to the Map, starting from lastIdx
func (tm *trillianMapper) PerformMapping(logAddress string, logPk string, logID, mapID int64, lastIdx int64) (int64, error) {
	logClient := tclient.NewLogClient(logAddress, logPk, tm.maxReceiveMessageSize)
	defer logClient.Close()
	// Get new certificates from log server
	logLeaves := logClient.RetrieveCerts(logID, lastIdx)
	if len(logLeaves) == 0 {
		return lastIdx, fmt.Errorf("No new logLeaves to map")
	}
	var certs [][]x509.Certificate
	for _, leaf := range logLeaves {
		cert, err := common.X509ParseCertificates(leaf.LeafValue)
		if err != nil {
			return lastIdx, fmt.Errorf("Failed to parse leaves from CT log: %s", err)
		}
		certs = append(certs, cert)
	}

	// log write domains to disk
	defer func() {
		err := tm.writeDomainsToFile()
		if err != nil {
			log.Printf("Error writing domains from file (%s,%s): %s", tm.ValidDomainsFile, tm.InvalidDomainsFile, err)
		}
	}()
	return tm.performMapping(certs, mapID, lastIdx, lastIdx+int64(len(logLeaves)), true)
}

func (tm *trillianMapper) PerformMappingFromProofs(proofs []tclient.Proof, mapID int64, batchSize int64) error {
	for i := 0; i < len(proofs); i++ {
		common.Debug("Mapping Proofs[%d,%d] ...", i, common.Min(int64(len(proofs)), int64(i)+batchSize))
		pBatch := proofs[i:common.Min(int64(len(proofs)), int64(i)+batchSize)]
		var batchCerts [][]x509.Certificate
		for _, p := range pBatch {
			batchCerts = append(batchCerts, p.GetAllCertificates()...)
		}
		_, err := tm.performMapping(batchCerts, mapID, 0, 0, false)
		if err != nil {
			return fmt.Errorf("Couldn't perform mapping from proofs[%d,%d]: %s", i, common.Min(int64(len(proofs)), int64(i)+batchSize), err)
		}
		common.Debug("Finished mapping proofs[%d,%d]", i, common.Min(int64(len(proofs)), int64(i)+batchSize))
	}
	return nil
}

func (tm *trillianMapper) performMapping(certificates [][]x509.Certificate, mapID int64, lastIdx int64, newLastIdx int64, updateLastIdx bool) (int64, error) {
	// Extract map entries and generate [domain -> map entry] map
	recursiveMapEntries, validDomains, invalidDomains, err := extractMapEntries(certificates)
	if err != nil {
		return lastIdx, fmt.Errorf("Failed to extract map entries from certificates: %s", err)
	}
	// log add domains
	for _, d := range validDomains {
		tm.validDomains[d] = true
	}
	for _, d := range invalidDomains {
		tm.invalidDomains[d] = true
	}
	// printRecursiveSubdomains(recursiveMapEntries, 0, 2)
	e2LDdomains := make([]string, len(recursiveMapEntries))
	i := 0
	for k := range recursiveMapEntries {
		e2LDdomains[i] = k
		i++
	}

	// create mock recursiveMapEntry with mapEntry = nil then call getsubdomaintreeroot on it
	globalREntry := &recursiveMapEntry{mapEntry: nil, subdomains: recursiveMapEntries}
	globalRootHash, err := tm.getSubdomainTreeRoot(globalREntry, mapID, tm.MapClient.GetMapPK(), "")
	if err != nil {
		return lastIdx, err
	}
	common.Debug("global root hash = %+v", globalRootHash)

	if updateLastIdx {
		common.Debug("Mapping performed, last leaf index: %d\n", newLastIdx)
		writeLastIdx(newLastIdx)
	}
	return newLastIdx, nil
}

// currentDomain is only used for debugging/logging purposes
func (tm *trillianMapper) getSubdomainTreeRoot(entry *recursiveMapEntry, mapID int64, mapPK crypto.PublicKey, currentDomain string) ([]byte, error) {
	verify := mapPK != nil

	// Find (sub-)domains that are being updated
	domains := make([]string, len(entry.subdomains))
	i := 0
	for k := range entry.subdomains {
		domains[i] = k
		i++
	}

	// Get map entries for these domains
	common.Debug("Fetching existing entries from mapID=%d for %s ...", mapID, currentDomain)
	// perform the merkle hash (inclusion) verification but don't check the signature if we don't have the map's public key
	encodedMapEntries, err := tm.MapClient.GetValues(mapID, mapPK, domains, verify, true)
	if err != nil {
		return nil, fmt.Errorf("Couldn't fetch values from map server to perform mapping: %s", err)
	}
	count := 0
	for _, e := range encodedMapEntries {
		if len(e.LeafValue) > 0 {
			count += 1
		}
	}
	common.Debug("Fetched %d non-empty entries", count)

	// Merge new and existing certificates and encode
	rEntries := entry.subdomains
	mergedMapEntries := make(map[string]tclient.EncodedMapEntry)
	for i, domain := range domains {
		rEntry := rEntries[domain]
		// subdomain status variables
		var hasSubdomains bool
		var subtreeRoot []byte
		var subtreeId int64

		// used for debugging
		var d string
		if currentDomain == "" {
			d = domain
		} else {
			d = domain + "." + currentDomain
		}
		common.Debug("Processing %s ...", d)

		// domain already exists
		if len(encodedMapEntries[i].LeafValue) > 0 {
			common.Debug("Updating existing entry")
			// unmarshal existing entry
			var existing tclient.MapEntryType
			err = existing.UnmarshalBinary(encodedMapEntries[i].LeafValue)
			if err != nil {
				return nil, fmt.Errorf("Couldn't unmarshal map entry data %s", err)
			}

			// merge entries
			common.Debug("Before merge: new=%+v, existing=%+v", rEntry.mapEntry.ToString(), existing.ToString())
			rEntry.mapEntry.Merge(&existing)
			common.Debug("After merge: new=%+v", rEntry.mapEntry.ToString())

			// keep existing subdomains if not changed by update
			hasSubdomains = encodedMapEntries[i].HasSubdomains
			copy(subtreeRoot, existing.SubtreeRoot)
			subtreeId = encodedMapEntries[i].SubdomainTreeId
		}

		// if this update affects subdomains
		if len(rEntry.subdomains) > 0 {
			common.Debug("Updating subdomains")
			// create map tree if it does not exist yet
			if !hasSubdomains {
				common.Debug("Creating anonymous map tree...")
				var err error
				subtreeId, err = createAnonymousMapTree(tm.MapClient.GetMapAddress())
				if err != nil {
					return nil, fmt.Errorf("Couldn't create anonymous map tree: %s", err)
				}
				common.Debug("Created anonymous map tree with mapID=%d", subtreeId)
			}
			hasSubdomains = true

			// recursively build map trees for subdomains
			subtreeRoot, err = tm.getSubdomainTreeRoot(rEntry, subtreeId, nil, d)
			if err != nil {
				return nil, fmt.Errorf("Error in domain %d: %s", d, err)
			}
		}
		rEntry.mapEntry.SubtreeRoot = subtreeRoot

		// marshal merged entries
		leafValue, err := rEntry.mapEntry.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("Couldn't marshal entry to binary: %s", err)
		}

		mergedMapEntries[domain] = tclient.EncodedMapEntry{LeafValue: leafValue, HasSubdomains: hasSubdomains, SubdomainTreeId: subtreeId}
	}

	// Set merged map entries
	err = tm.MapClient.SetValues(mapID, mapPK, mergedMapEntries, verify)
	if err != nil {
		return nil, fmt.Errorf("Failed to set key:value pairs in map server: %s", err)
	}

	// retrieve MHT root hash
	root, err := tm.MapClient.GetMapRoot(mapID, mapPK, false)
	if err != nil {
		return nil, fmt.Errorf("Failed to get map root: %s", err)
	}
	common.Debug("Returning update root hash (%x) for domain %s and subtreeId=%d", root.RootHash, currentDomain, mapID)
	return root.RootHash, nil
}

func extractMapEntries(certificates [][]x509.Certificate) (map[string]*recursiveMapEntry, []string, []string, error) {
	mapEntries := make(map[string]*recursiveMapEntry)
	var validDomains, invalidDomains []string
	for _, cert := range certificates {
		for _, domain := range common.DomainsFromX509Cert(&cert[0]) {
			if !common.IsViableDomain(domain) {
				invalidDomains = append(invalidDomains, domain)
				continue
			}

			s, err := common.SplitE2LD(domain)
			if err != nil {
				invalidDomains = append(invalidDomains, domain)
				continue
				// return nil, validDomains, invalidDomains, fmt.Errorf("Couldn't split '%s' into subdomains: %s", domain, err)
			}

			validDomains = append(validDomains, domain)

			// reverse to start at E2LD
			for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
				s[i], s[j] = s[j], s[i]
			}

			var entry, oldEntry *recursiveMapEntry
			for i, d := range s {
				var quitLoop bool
				// read entry
				if i == 0 {
					if _, ok := mapEntries[d]; !ok {
						mapEntries[d] = &recursiveMapEntry{subdomains: make(map[string]*recursiveMapEntry)}
					}
					entry = mapEntries[d]
				} else {
					oldEntry = entry
					if _, ok := entry.subdomains[d]; !ok {
						entry.subdomains[d] = &recursiveMapEntry{subdomains: make(map[string]*recursiveMapEntry)}
					}
					entry = entry.subdomains[d]
				}

				if entry.mapEntry == nil {
					entry.mapEntry = &tclient.MapEntryType{}
				}
				// update entry
				var add tclient.MapEntryType
				if i == len(s)-1 {
					add.Certificates = append(add.Certificates, cert)
				} else if i == len(s)-2 && common.IsWildcardLabel(s[len(s)-1]) {
					add.WildcardCertificates = append(add.WildcardCertificates, cert)
					quitLoop = true
				}
				entry.mapEntry.Merge(&add)

				// write entry
				if i == 0 {
					mapEntries[d] = entry
				} else {
					oldEntry.subdomains[d] = entry
				}

				if quitLoop {
					break
				}
			}
		}
	}
	return mapEntries, validDomains, invalidDomains, nil
}

func printRecursiveSubdomains(r map[string]*recursiveMapEntry, indent, indentStep int) {
	if len(r) == 0 {
		return
	}
	for domain, entry := range r {
		var nCerts, nWildcardCerts int
		if entry.mapEntry != nil {
			nCerts = len(entry.mapEntry.Certificates)
			nWildcardCerts = len(entry.mapEntry.WildcardCertificates)
		}
		log.Printf("%s%s: %d certs, %d wildcard certs", strings.Repeat(" ", indent), domain, nCerts, nWildcardCerts)
		printRecursiveSubdomains(entry.subdomains, indent+indentStep, indentStep)
	}
}

func createAnonymousMapTree(adminServerAddress string) (int64, error) {
	ts, ok := trillian.TreeState_value[trillian.TreeState_ACTIVE.String()]
	if !ok {
		return 0, fmt.Errorf("unknown TreeState: %v", trillian.TreeState_ACTIVE.String())
	}

	tt, ok := trillian.TreeType_value[trillian.TreeType_MAP.String()]
	if !ok {
		return 0, fmt.Errorf("unknown TreeType: %v", trillian.TreeType_MAP.String())
	}

	hs, ok := trillian.HashStrategy_value[trillian.HashStrategy_TEST_MAP_HASHER.String()]
	if !ok {
		return 0, fmt.Errorf("unknown HashStrategy: %v", trillian.HashStrategy_TEST_MAP_HASHER.String())
	}

	ha, ok := sigpb.DigitallySigned_HashAlgorithm_value[sigpb.DigitallySigned_SHA256.String()]
	if !ok {
		return 0, fmt.Errorf("unknown HashAlgorithm: %v", sigpb.DigitallySigned_SHA256.String())
	}

	sa, ok := sigpb.DigitallySigned_SignatureAlgorithm_value[sigpb.DigitallySigned_ECDSA.String()]
	if !ok {
		return 0, fmt.Errorf("unknown SignatureAlgorithm: %v", sigpb.DigitallySigned_ANONYMOUS.String())
	}

	maxDuration, err := time.ParseDuration("0")
	common.LogError("Couldn't parse zero duration: %s", err)

	//TODO(cyrill) clean up the above mess and directly set correct values
	req := &trillian.CreateTreeRequest{Tree: &trillian.Tree{
		TreeState:          trillian.TreeState(ts),
		TreeType:           trillian.TreeType(tt),
		HashStrategy:       trillian.HashStrategy(hs),
		HashAlgorithm:      sigpb.DigitallySigned_HashAlgorithm(ha),
		SignatureAlgorithm: sigpb.DigitallySigned_SignatureAlgorithm(sa),
		DisplayName:        "",
		Description:        "",
		MaxRootDuration:    ptypes.DurationProto(maxDuration),
	}}

	//TODO(cyrill) how can we not generate a key for anonymous (no) signing?
	req.KeySpec = &keyspb.Specification{}

	switch sigpb.DigitallySigned_SignatureAlgorithm(sa) {
	case sigpb.DigitallySigned_ECDSA:
		req.KeySpec.Params = &keyspb.Specification_EcdsaParams{
			EcdsaParams: &keyspb.Specification_ECDSA{},
		}
	case sigpb.DigitallySigned_RSA:
		req.KeySpec.Params = &keyspb.Specification_RsaParams{
			RsaParams: &keyspb.Specification_RSA{},
		}
	default:
		log.Fatalf("unsupported signature algorithm: %v", sa)
	}

	dialOpts, err := rpcflags.NewClientDialOptionsFromFlags()
	if err != nil {
		return 0, fmt.Errorf("failed to determine dial options: %v", err)
	}

	conn, err := grpc.Dial(adminServerAddress, dialOpts...)
	if err != nil {
		return 0, fmt.Errorf("failed to dial %v: %v", adminServerAddress, err)
	}
	defer conn.Close()

	adminClient := trillian.NewTrillianAdminClient(conn)
	mapClient := trillian.NewTrillianMapClient(conn)
	logClient := trillian.NewTrillianLogClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	tree, err := client.CreateAndInitTree(ctx, req, adminClient, mapClient, logClient)
	common.LogError("Failed to create tree: %s", err)

	return tree.TreeId, nil
}

func writeLastIdx(lastIdx int64) {
	file, err := os.Create("trillian/lastIdx")
	common.LogError("Failed to create lastIdx file: %s", err)
	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("%d", lastIdx))
	common.LogError("Failed writing lastIdx to file: %s", err)

}

func (tm *trillianMapper) Close() {
	tm.MapClient.Close()
	tm.DroppedLogEntryWriter.Close()
}
