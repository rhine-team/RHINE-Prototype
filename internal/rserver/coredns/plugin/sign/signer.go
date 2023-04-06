package sign

import (
	"fmt"
	"io"
	lout "log"
	"os"
	"path/filepath"
	"time"

	"github.com/coredns/coredns/plugin/file"
	"github.com/coredns/coredns/plugin/file/tree"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"
	"github.com/rhine-team/RHINE-Prototype/pkg/rhine"
)

var log = clog.NewWithPlugin("sign")

// Signer holds the data needed to sign a zone file.
type Signer struct {
	keys        []Pair
	rCertPair   *RCertPair
	origin      string
	dbfile      string
	directory   string
	jitterIncep time.Duration
	jitterExpir time.Duration

	signedfile string
	stop       chan struct{}
}

// Sign signs a zone file according to the parameters in s.
func (s *Signer) Sign(now time.Time) (*file.Zone, error) {
	rd, err := os.Open(s.dbfile)
	if err != nil {
		return nil, err
	}

	z, err := Parse(rd, s.origin, s.dbfile)
	if err != nil {
		return nil, err
	}

	//mttl := z.Apex.SOA.Minttl
	ttl := z.Apex.SOA.Header().Ttl
	inception, expiration := lifetime(now, s.jitterIncep, s.jitterExpir)
	z.Apex.SOA.Serial = uint32(now.Unix())

	for _, pair := range s.keys {
		pair.Public.Header().Ttl = ttl // set TTL on key so it matches the RRSIG.
		z.Insert(pair.Public)
		//z.Insert(pair.Public.ToDS(dns.SHA1).ToCDS())
		//z.Insert(pair.Public.ToDS(dns.SHA256).ToCDS())
		//z.Insert(pair.Public.ToCDNSKEY())
		sig, err := signZSK(pair.Public, s.rCertPair.Private, s.origin, ttl, inception, expiration)
		if err != nil {
			return nil, err
		}
		z.Insert(sig)
	}

	//names := names(s.origin, z)
	//ln := len(names)

	for _, pair := range s.keys {
		rrsig, err := pair.signRRs([]dns.RR{z.Apex.SOA}, s.origin, ttl, inception, expiration)
		if err != nil {
			return nil, err
		}
		z.Insert(rrsig)
		// NS apex may not be set if RR's have been discarded because the origin doesn't match.
		if len(z.Apex.NS) > 0 {
			rrsig, err = pair.signRRs(z.Apex.NS, s.origin, ttl, inception, expiration)
			if err != nil {
				return nil, err
			}
			z.Insert(rrsig)
		}
	}

	// We are walking the tree in the same direction, so names[] can be used here to indicated the next element.
	i := 1
	err = z.AuthWalk(func(e *tree.Elem, zrrs map[uint16][]dns.RR, auth bool) error {
		if !auth {
			return nil
		}

		//if e.Name() == s.origin {
		//	nsec := NSEC(e.Name(), names[(ln+i)%ln], mttl, append(e.Types(), dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC))
		//	z.Insert(nsec)
		//} else {
		//	nsec := NSEC(e.Name(), names[(ln+i)%ln], mttl, append(e.Types(), dns.TypeRRSIG, dns.TypeNSEC))
		//	z.Insert(nsec)
		//}

		for t, rrs := range zrrs {
			// RRSIGs are not signed and NS records are not signed because we are never authoratiative for them.
			// The zone's apex nameservers records are not kept in this tree and are signed separately.
			if t == dns.TypeRRSIG || t == dns.TypeNS || t == dns.TypeDNSKEY {
				continue
			}
			for _, pair := range s.keys {
				rrsig, err := pair.signRRs(rrs, s.origin, rrs[0].Header().Ttl, inception, expiration)
				if err != nil {
					return err
				}
				e.Insert(rrsig)
			}
		}
		i++
		return nil
	})
	z.Insert(createCertRR(s.rCertPair.Rcert, s.origin))

	pwd, _ := os.Getwd()
	lout.Println("Current dir: ", pwd)
	lout.Println("Origin value ", s.origin)

	parentToChild := make(map[string]string)
	parentToChild["."] = "com."
	parentToChild["com."] = "rhine-test.com."
	parentToChild["rhine-test.com."] = "test.rhine-test.com"

	// Inser DSAProofs
	// TODO: DSA input

	var parname string
	if s.origin == "." {
		parname = "root"
	} else if s.origin == "com." {
		parname = "com"
	} else {
		parname = "rhine-test.com"
	}
	parentCertPath := "../../testdata/nameserver/zones/rcerts/" + parname + "_cert.pem"
	cert, errcert := rhine.LoadCertificatePEM(parentCertPath)
	if errcert != nil {
		log.Fatal("Error loading certificate: ", err)
	}
	pCert := rhine.ExtractTbsRCAndHash(cert, false)
	expirationTime := time.Now().Add(time.Hour * 24 * 180)
	aL := rhine.AuthorityLevel(0b0000)
	content := []rhine.DSLeafContent{}
	newDelegZone := rhine.DSLeafZone{
		Zone:     parentToChild[s.origin],
		Alv:      aL,
		ZoneType: rhine.ExistingZone,
	}
	content = rhine.InsertNewDSLeafZone(content, newDelegZone)

	newTree, errtree := rhine.NewTree(content)
	if errtree != nil {
		log.Fatal("Error tree making.")
	}

	lout.Println("Content: ", content)
	dsa := &rhine.DSA{
		Zone:     s.origin,
		Alv:      aL,
		Exp:      expirationTime,
		Cert:     pCert,
		Acc:      newTree,
		Subzones: content,
	}

	for _, leafzone := range dsa.Subzones {
		// Create a DSAProof of presence for every child
		mp, resbool, err := dsa.GetMPathProofPresence(leafzone.Start.Zone)
		if !resbool || err != nil {
			fmt.Println("Error: Could not create a MProof. Error, then bool:", err, resbool)
			continue
		}
		// Add result as a record
		// TODO: look at zone name again
		var namez string
		if leafzone.Start.Zone == "" {
			namez = "-infinity"
		} else {
			namez = leafzone.Start.Zone
		}
		lout.Println("Namez: ", namez)
		z.Insert(createDSAProofRR(mp, namez))

	}
	// Insert DSum
	// TODO: DSum input
	var dsum *rhine.DSumNR
	dsum = dsa.GetDSumNR([]string{"Logger1"})
	// Sign
	// Read in logger Privkey
	privkeypath := "../../testdata/nameserver/zones/loggerkey/Logger1_priv.pem"
	privkey, errkey := rhine.LoadPrivateKeyEd25519(privkeypath)
	if errkey != nil {
		fmt.Println("Error when reading logger priv key")
		log.Fatal("Could not read privkey")
	}
	dsum.SignOne("Logger1", privkey)
	z.Insert(createDSumRR(dsum, s.origin))

	return z, err
}

// resign checks if the signed zone exists, or needs resigning.
func (s *Signer) resign() error {
	signedfile := filepath.Join(s.directory, s.signedfile)
	rd, err := os.Open(filepath.Clean(signedfile))
	if err != nil && os.IsNotExist(err) {
		return err
	}

	now := time.Now().UTC()
	return resign(rd, now)
}

// resign will scan rd and check the signature on the SOA record. We will resign on the basis
// of 2 conditions:
// * either the inception is more than 6 days ago, or
// * we only have 1 week left on the signature
//
// All SOA signatures will be checked. If the SOA isn't found in the first 100
// records, we will resign the zone.
func resign(rd io.Reader, now time.Time) (why error) {
	zp := dns.NewZoneParser(rd, ".", "resign")
	zp.SetIncludeAllowed(true)
	i := 0

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if err := zp.Err(); err != nil {
			return err
		}

		switch x := rr.(type) {
		case *dns.RRSIG:
			if x.TypeCovered != dns.TypeSOA {
				continue
			}
			incep, _ := time.Parse("20060102150405", dns.TimeToString(x.Inception))
			// If too long ago, resign.
			if now.Sub(incep) >= 0 && now.Sub(incep) > durationResignDays {
				return fmt.Errorf("inception %q was more than: %s ago from %s: %s", incep.Format(timeFmt), durationResignDays, now.Format(timeFmt), now.Sub(incep))
			}
			// Inception hasn't even start yet.
			if now.Sub(incep) < 0 {
				return fmt.Errorf("inception %q date is in the future: %s", incep.Format(timeFmt), now.Sub(incep))
			}

			expire, _ := time.Parse("20060102150405", dns.TimeToString(x.Expiration))
			if expire.Sub(now) < durationExpireDays {
				return fmt.Errorf("expiration %q is less than: %s away from %s: %s", expire.Format(timeFmt), durationExpireDays, now.Format(timeFmt), expire.Sub(now))
			}
		}
		i++
		if i > 100 {
			// 100 is a random number. A SOA record should be the first in the zonefile, but RFC 1035 doesn't actually mandate this. So it could
			// be 3rd or even later. The number 100 looks crazy high enough that it will catch all weird zones, but not high enough to keep the CPU
			// busy with parsing all the time.
			return fmt.Errorf("no SOA RRSIG found in first 100 records")
		}
	}

	return nil
}

func signAndLog(s *Signer, why error) {
	now := time.Now().UTC()
	z, err := s.Sign(now)
	log.Infof("Signing %q because %s", s.origin, why)
	if err != nil {
		log.Warningf("Error signing %q with key tags %q in %s: %s, next: %s", s.origin, keyTag(s.keys), time.Since(now), err, now.Add(durationRefreshHours).Format(timeFmt))
		return
	}

	if err := s.write(z); err != nil {
		log.Warningf("Error signing %q: failed to move zone file into place: %s", s.origin, err)
		return
	}
	log.Infof("Successfully signed zone %q in %q with key tags %q and %d SOA serial, elapsed %f, next: %s", s.origin, filepath.Join(s.directory, s.signedfile), keyTag(s.keys), z.Apex.SOA.Serial, time.Since(now).Seconds(), now.Add(durationRefreshHours).Format(timeFmt))
}

// refresh checks every val if some zones need to be resigned.
func (s *Signer) refresh(val time.Duration) {
	tick := time.NewTicker(val)
	defer tick.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-tick.C:
			why := s.resign()
			if why == nil {
				continue
			}
			signAndLog(s, why)
		}
	}
}

func lifetime(now time.Time, jitterInception, jitterExpiration time.Duration) (uint32, uint32) {
	incep := uint32(now.Add(durationSignatureInceptionHours).Add(jitterInception).Unix())
	expir := uint32(now.Add(durationSignatureExpireDays).Add(jitterExpiration).Unix())
	return incep, expir
}
