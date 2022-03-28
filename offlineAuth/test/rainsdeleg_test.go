package test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	logger "github.com/inconshreveable/log15"
	"github.com/rhine-team/RHINE-Prototype/ca"
	"github.com/rhine-team/RHINE-Prototype/checkerExtension"
	"github.com/rhine-team/RHINE-Prototype/child"
	"github.com/rhine-team/RHINE-Prototype/common"
	"github.com/rhine-team/RHINE-Prototype/keyManager"
	"github.com/rhine-team/RHINE-Prototype/parent"
	"io/ioutil"
	random "math/rand"
	"os"
	"testing"
	"time"
)

const (
	MAP_ADDRESS     = "172.18.0.5:8094"
	CA_ADDRESS      = "localhost:10000"
	CHECKER_ADDRESS = "localhost:10001"
	LOG_ADDRESS     = "172.18.0.3:8090"
	MAP_PK_PATH     = "testdata/mappk1.pem"
	LOG_PK_PATH     = "testdata/logpk1.pem"
	MAP_ID          = 3213023363744691885
	LOG_ID          = 8493809986858120401
)

func TestNewDlgEd25519Keys(t *testing.T) {
	logger.Root().SetHandler(logger.StreamHandler(os.Stdout, logger.TerminalFormat()))

	ca_conf, _ := ca.LoadConfig("testdata/configs/caconfig.conf")
	parent_conf, _ := parent.LoadConfig("testdata/configs/ch_parentconfig.conf")
	checker_conf, _ := checkerExtension.LoadConfig("testdata/configs/checkerconfig.conf")

	ca := ca.NewCA(ca_conf)
	go ca.RunServer("localhost:10000")
	parent := parent.NewParent(parent_conf)
	checker := checkerExtension.NewChecker(checker_conf)
	go checker.RunServer("localhost:10001")

	_, childPrivKey, _ := ed25519.GenerateKey(rand.Reader)
	random.Seed(time.Now().UnixNano())
	testid := fmt.Sprint(random.Intn(10000))
	csrbytes, _ := child.CreateCSR("test"+testid+"."+parent.Certificate.DNSNames[0], "", childPrivKey)

	_, err := parent.NewDlg(csrbytes, true)
	if err != nil {
		t.Errorf("NewDlg failed")
	}

	time.Sleep(time.Second)

	_, err = parent.NewDlg(csrbytes, true)
	if err == nil {
		t.Errorf("Parent NewDlg not blocked")
	}

}

func TestNewDlgRSAKeys(t *testing.T) {
	logger.Root().SetHandler(logger.StreamHandler(os.Stdout, logger.TerminalFormat()))

	ca_conf, _ := ca.LoadConfig("testdata/configs/ca2config.conf")
	parent_conf, _ := parent.LoadConfig("testdata/configs/com_parentconfig.conf")
	checker_conf, _ := checkerExtension.LoadConfig("testdata/configs/checkerconfig.conf")

	ca := ca.NewCA(ca_conf)
	go ca.RunServer("localhost:10000")
	parent := parent.NewParent(parent_conf)
	checker := checkerExtension.NewChecker(checker_conf)
	go checker.RunServer("localhost:10001")

	childPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	random.Seed(time.Now().UnixNano())
	testid := fmt.Sprint(random.Intn(10000))
	csrbytes, _ := child.CreateCSR("test"+testid+"."+parent.Certificate.DNSNames[0], "", childPrivKey)

	_, err := parent.NewDlg(csrbytes, true)
	if err != nil {
		t.Errorf("NewDlg failed")
	}
	time.Sleep(time.Second)
	_, err = parent.NewDlg(csrbytes, true)
	if err == nil {
		t.Errorf("Parent NewDlg not blocked")
	}

}

func TestNewDlgReNewDlgKeyChangeDlg(t *testing.T) {
	logger.Root().SetHandler(logger.StreamHandler(os.Stdout, logger.TerminalFormat()))

	ca_conf, _ := ca.LoadConfig("testdata/configs/ca2config.conf")
	parent_conf, _ := parent.LoadConfig("testdata/configs/ch_parentconfig.conf")
	checker_conf, _ := checkerExtension.LoadConfig("testdata/configs/checkerconfig.conf")

	ca := ca.NewCA(ca_conf)
	go ca.RunServer("localhost:10000")
	parent := parent.NewParent(parent_conf)
	checker := checkerExtension.NewChecker(checker_conf)
	go checker.RunServer("localhost:10001")

	_, childPrivKey, _ := ed25519.GenerateKey(rand.Reader)
	random.Seed(time.Now().UnixNano())
	testid := fmt.Sprint(random.Intn(10000))
	csrbytes, _ := child.CreateCSR("test"+testid+"."+parent.Certificate.DNSNames[0], "", childPrivKey)

	childCert, err := parent.NewDlg(csrbytes, true)
	//common.StoreCertificatePEM("testrun.cert", childCert)
	if err != nil {
		t.Errorf("NewDlg failed %s", err)
		return
	}

	time.Sleep(time.Second)

	_, err = parent.NewDlg(csrbytes, true)
	if err == nil {
		t.Errorf("Parent NewDlg not blocked")
	}

	childCertParsed, _ := x509.ParseCertificate(childCert)
	renewedCert, err := child.ReNewDlg(childCertParsed, childPrivKey, "localhost:10000", "localhost:10001")
	if err != nil {
		t.Errorf("Child ReNewDlg failed")
		return
	}

	renewedCertParsed, _ := x509.ParseCertificate(renewedCert)
	newKey1, _ := rsa.GenerateKey(rand.Reader, 2048)

	newKey1Cert, err := child.KeyChangeDlg(renewedCertParsed, childPrivKey, newKey1, "localhost:10000", "localhost:10001")
	if err != nil {
		t.Errorf("Key Change failed")
		return
	}

	newKey1CertParsed, _ := x509.ParseCertificate(newKey1Cert)
	_, newKey2, _ := ed25519.GenerateKey(rand.Reader)

	_, err = child.KeyChangeDlg(newKey1CertParsed, newKey1, newKey2, "localhost:10000", "localhost:10001")
	if err != nil {
		t.Errorf("Key Change failed")
		return
	}

}
func TestFull(t *testing.T) {
	logger.Root().SetHandler(logger.StreamHandler(os.Stdout, logger.TerminalFormat()))

	var alg = "Ed25519"

	//create a CA:
	ca_alg := alg
	ca_key_path := "testfulldata/ca.key"
	ca_cert_path := "testfulldata/ca.cert"
	keyManager.CreateEd25519Key(ca_key_path)
	keyManager.CreateSelfSignedCACertificate(ca_alg, ca_key_path, ca_cert_path)
	cert, _ := common.LoadCertificatePEM(ca_cert_path)
	common.StoreCertificatePEM("testfulldata/roots/ca.cert", cert.Raw)

	ca_config := ca.Config{
		PrivateKeyAlgorithm:    ca_alg,
		PrivateKeyPath:         ca_key_path,
		CertificatePath:        ca_cert_path,
		MapServerAddress:       MAP_ADDRESS,
		MapServerPublicKeyPath: MAP_PK_PATH,
		MapId:                  MAP_ID,
		ServerAddress:          CA_ADDRESS,
		RootCertsPath:          "testfulldata/roots/",
	}
	CA := ca.NewCA(ca_config)
	go CA.RunServer(CA_ADDRESS)

	checker_config := checkerExtension.Config{
		LogID:         LOG_ID,
		LogAddress:    LOG_ADDRESS,
		LogPkeyPath:   LOG_PK_PATH,
		MapID:         MAP_ID,
		MapAddress:    MAP_ADDRESS,
		MapPkeyPath:   MAP_PK_PATH,
		RootCertsPath: "testfulldata/roots/",
		ServerAddress: CHECKER_ADDRESS,
	}
	CHECKER := checkerExtension.NewChecker(checker_config)
	go CHECKER.RunServer(CHECKER_ADDRESS)

	// random test number
	random.Seed(time.Now().UnixNano())
	testid := fmt.Sprint(random.Intn(10000))

	//create root parent zone with no authentication (instead of using dnssec)
	root_alg := alg
	root_key_path := "testfulldata/root.key"
	keyManager.CreateEd25519Key(root_key_path)
	root_config := parent.Config{
		Zone:                 "rhine",
		AuthenticationType:   "NOAUTH",
		LogCheckerExtAddress: CHECKER_ADDRESS,
		PrivateKeyAlgorithm:  root_alg,
		PrivateKeyPath:       root_key_path,
		CertificatePath:      "",
		CAAddress:            CA_ADDRESS,
		OutputDir:            "",
	}
	ROOT := parent.NewParent(root_config)

	tld_alg := alg
	tld_key_path := "testfulldata/tld.key"
	keyManager.CreateEd25519Key(tld_key_path)
	tld_key, _ := common.LoadPrivateKeyEd25519(tld_key_path)

	tld_zone := "tld" + testid + "." + root_config.Zone
	tld_csr, _ := child.CreateCSR(tld_zone, "", tld_key)

	common.StoreCertificateRequestPEM("testfulldata/debugcsr.csr", tld_csr)

	tld_cert, err := ROOT.NewDlg(tld_csr, true)
	if err != nil {
		fmt.Println(err)
		t.Errorf("Root NewDlg failed")
		return
	}

	tld_cert_parsed, _ := x509.ParseCertificate(tld_cert)
	fmt.Println(tld_cert_parsed.Extensions)

	tld_cert_path := "testfulldata/tld.cert"
	common.StoreCertificatePEM(tld_cert_path, tld_cert)

	tld_config := parent.Config{
		Zone:                 tld_zone,
		AuthenticationType:   "certificate",
		LogCheckerExtAddress: CHECKER_ADDRESS,
		PrivateKeyAlgorithm:  tld_alg,
		PrivateKeyPath:       tld_key_path,
		CertificatePath:      tld_cert_path,
		CAAddress:            CA_ADDRESS,
		OutputDir:            "",
	}
	TLD := parent.NewParent(tld_config)

	_, SLDKey, _ := ed25519.GenerateKey(rand.Reader)
	SLDcsrbytes, _ := child.CreateCSR("sld"+testid+"."+TLD.Certificate.DNSNames[0], "", SLDKey)

	SLDcert, err := TLD.NewDlg(SLDcsrbytes, true)
	if err != nil {
		t.Errorf("SLD NewDlg failed %s", err)
		return
	}
	common.StoreCertificatePEM("testfulldata/sld.cert", SLDcert)

	time.Sleep(time.Second * 2)

	_, err = TLD.NewDlg(SLDcsrbytes, true)
	if err == nil {
		t.Errorf("TLD NewDlg for SLD not blocked")
		return
	}

	sldCertParsed, _ := x509.ParseCertificate(SLDcert)
	renewedCert, err := child.ReNewDlg(sldCertParsed, SLDKey, CA_ADDRESS, CHECKER_ADDRESS)
	if err != nil {
		t.Errorf("SLD ReNewDlg failed")
		return
	}

	renewedCertParsed, _ := x509.ParseCertificate(renewedCert)
	newKey1, _ := rsa.GenerateKey(rand.Reader, 2048)

	newKey1Cert, err := child.KeyChangeDlg(renewedCertParsed, SLDKey, newKey1, CA_ADDRESS, CHECKER_ADDRESS)
	if err != nil {
		t.Errorf("Key Change failed")
		return
	}

	newKey1CertParsed, _ := x509.ParseCertificate(newKey1Cert)
	_, newKey2, _ := ed25519.GenerateKey(rand.Reader)

	_, err = child.KeyChangeDlg(newKey1CertParsed, newKey1, newKey2, CA_ADDRESS, CHECKER_ADDRESS)
	if err != nil {
		t.Errorf("Key Change failed")
		return
	}

}

func TestRevoke(t *testing.T) {
	logger.Root().SetHandler(logger.StreamHandler(os.Stdout, logger.TerminalFormat()))

	var alg = "Ed25519"

	//create a CA:
	ca_alg := alg
	ca_key_path := "testfulldata/ca.key"
	ca_cert_path := "testfulldata/ca.cert"
	keyManager.CreateEd25519Key(ca_key_path)
	keyManager.CreateSelfSignedCACertificate(ca_alg, ca_key_path, ca_cert_path)
	cert, _ := common.LoadCertificatePEM(ca_cert_path)
	common.StoreCertificatePEM("testfulldata/roots/ca.cert", cert.Raw)

	ca_config := ca.Config{
		PrivateKeyAlgorithm:    ca_alg,
		PrivateKeyPath:         ca_key_path,
		CertificatePath:        ca_cert_path,
		MapServerAddress:       MAP_ADDRESS,
		MapServerPublicKeyPath: MAP_PK_PATH,
		MapId:                  MAP_ID,
		ServerAddress:          CA_ADDRESS,
		RootCertsPath:          "testfulldata/roots/",
	}
	CA := ca.NewCA(ca_config)
	go CA.RunServer(CA_ADDRESS)

	checker_config := checkerExtension.Config{
		LogID:         LOG_ID,
		LogAddress:    LOG_ADDRESS,
		LogPkeyPath:   LOG_PK_PATH,
		MapID:         MAP_ID,
		MapAddress:    MAP_ADDRESS,
		MapPkeyPath:   MAP_PK_PATH,
		RootCertsPath: "testfulldata/roots/",
		ServerAddress: CHECKER_ADDRESS,
	}
	CHECKER := checkerExtension.NewChecker(checker_config)
	go CHECKER.RunServer(CHECKER_ADDRESS)

	// random test number
	random.Seed(time.Now().UnixNano())
	testid := fmt.Sprint(random.Intn(10000))

	//create root parent zone with no authentication (instead of using dnssec)
	root_alg := alg
	root_key_path := "testfulldata/root.key"
	keyManager.CreateEd25519Key(root_key_path)
	root_config := parent.Config{
		Zone:                 "rhine",
		AuthenticationType:   "NOAUTH",
		LogCheckerExtAddress: CHECKER_ADDRESS,
		PrivateKeyAlgorithm:  root_alg,
		PrivateKeyPath:       root_key_path,
		CertificatePath:      "",
		CAAddress:            CA_ADDRESS,
		OutputDir:            "",
	}
	ROOT := parent.NewParent(root_config)

	tld_alg := alg
	tld_key_path := "testfulldata/tld.key"
	keyManager.CreateEd25519Key(tld_key_path)
	tld_key, _ := common.LoadPrivateKeyEd25519(tld_key_path)

	tld_zone := "tld" + testid + "." + root_config.Zone
	tld_csr, _ := child.CreateCSR(tld_zone, "", tld_key)

	common.StoreCertificateRequestPEM("testfulldata/debugcsr.csr", tld_csr)

	tld_cert, err := ROOT.NewDlg(tld_csr, true)
	if err != nil {
		fmt.Println(err)
		t.Errorf("Root NewDlg failed")
		return
	}

	tld_cert_parsed, _ := x509.ParseCertificate(tld_cert)
	fmt.Println(tld_cert_parsed.Extensions)

	tld_cert_path := "testfulldata/tld.cert"
	common.StoreCertificatePEM(tld_cert_path, tld_cert)

	tld_config := parent.Config{
		Zone:                 tld_zone,
		AuthenticationType:   "certificate",
		LogCheckerExtAddress: CHECKER_ADDRESS,
		PrivateKeyAlgorithm:  tld_alg,
		PrivateKeyPath:       tld_key_path,
		CertificatePath:      tld_cert_path,
		CAAddress:            CA_ADDRESS,
		OutputDir:            "",
	}
	TLD := parent.NewParent(tld_config)

	_, SLDKey, _ := ed25519.GenerateKey(rand.Reader)
	SLDcsrbytes, _ := child.CreateCSR("sld"+testid+"."+TLD.Certificate.DNSNames[0], "", SLDKey)

	SLDcert, err := TLD.NewDlg(SLDcsrbytes, true)
	if err != nil {
		t.Errorf("SLD NewDlg failed %s", err)
		return
	}
	common.StoreCertificatePEM("testfulldata/sld.cert", SLDcert)

	//revoke sld cert
	SLDCertParsed, _ := x509.ParseCertificate(SLDcert)
	err = child.RevokeDlg(SLDCertParsed, SLDKey, CHECKER_ADDRESS)
	if err != nil {
		t.Errorf("Revoke failed %s", err)
		return
	}

	time.Sleep(time.Second * 2)

	_, err = TLD.NewDlg(SLDcsrbytes, true)
	if err != nil {
		t.Errorf("TLD NewDlg still blocked (should not because of revocation)")
		return
	}

}

func TestCreateDemoFiles(t *testing.T) {
	logger.Root().SetHandler(logger.StreamHandler(os.Stdout, logger.TerminalFormat()))

	var demotld = "ch1"

	var alg = "Ed25519"

	//create a CA:
	ca_alg := alg
	ca_key_path := "testfulldata/ca.key"
	ca_cert_path := "testfulldata/ca.cert"
	keyManager.CreateEd25519Key(ca_key_path)
	keyManager.CreateSelfSignedCACertificate(ca_alg, ca_key_path, ca_cert_path)
	cert, _ := common.LoadCertificatePEM(ca_cert_path)
	common.StoreCertificatePEM("testfulldata/roots/ca.cert", cert.Raw)

	ca_config := ca.Config{
		PrivateKeyAlgorithm:    ca_alg,
		PrivateKeyPath:         ca_key_path,
		CertificatePath:        ca_cert_path,
		MapServerAddress:       MAP_ADDRESS,
		MapServerPublicKeyPath: MAP_PK_PATH,
		MapId:                  MAP_ID,
		ServerAddress:          CA_ADDRESS,
		RootCertsPath:          "testfulldata/roots/",
	}

	ca_conf_file, _ := json.MarshalIndent(ca_config, "", " ")
	_ = ioutil.WriteFile("testfulldata/ca.conf", ca_conf_file, 0644)

	CA := ca.NewCA(ca_config)
	go CA.RunServer(CA_ADDRESS)

	checker_config := checkerExtension.Config{
		LogID:         LOG_ID,
		LogAddress:    LOG_ADDRESS,
		LogPkeyPath:   LOG_PK_PATH,
		MapID:         MAP_ID,
		MapAddress:    MAP_ADDRESS,
		MapPkeyPath:   MAP_PK_PATH,
		RootCertsPath: "testfulldata/roots/",
		ServerAddress: CHECKER_ADDRESS,
	}

	checker_conf_file, _ := json.MarshalIndent(checker_config, "", " ")
	_ = ioutil.WriteFile("testfulldata/checker.conf", checker_conf_file, 0644)

	CHECKER := checkerExtension.NewChecker(checker_config)
	go CHECKER.RunServer(CHECKER_ADDRESS)

	// random test number
	//random.Seed(time.Now().UnixNano())
	//testid := fmt.Sprint(random.Intn(10000))

	//create root parent zone with no authentication (instead of using dnssec)
	root_alg := alg
	root_key_path := "testfulldata/root.key"
	keyManager.CreateEd25519Key(root_key_path)
	root_config := parent.Config{
		Zone:                 "rhine",
		AuthenticationType:   "NOAUTH",
		LogCheckerExtAddress: CHECKER_ADDRESS,
		PrivateKeyAlgorithm:  root_alg,
		PrivateKeyPath:       root_key_path,
		CertificatePath:      "",
		CAAddress:            CA_ADDRESS,
		OutputDir:            "testfulldata/",
	}

	root_conf_file, _ := json.MarshalIndent(root_config, "", " ")
	_ = ioutil.WriteFile("testfulldata/root.conf", root_conf_file, 0644)

	ROOT := parent.NewParent(root_config)

	tld_alg := alg
	tld_key_path := "testfulldata/tld.key"
	keyManager.CreateEd25519Key(tld_key_path)
	tld_key, _ := common.LoadPrivateKeyEd25519(tld_key_path)

	tld_zone := demotld + ".rhine"
	tld_csr, _ := child.CreateCSR(tld_zone, "", tld_key)

	fmt.Println("len csr", len(tld_csr))
	common.StoreCertificateRequestPEM("testfulldata/debugcsr.csr", tld_csr)

	tld_cert, err := ROOT.NewDlg(tld_csr, true)
	if err != nil {
		fmt.Println(err)
		t.Errorf("Root NewDlg failed")
		return
	}

	fmt.Println("TLD Cert Size Ed25519", len(tld_cert))

	tld_cert_parsed, _ := x509.ParseCertificate(tld_cert)
	fmt.Println(tld_cert_parsed.Extensions)

	tld_cert_path := "testfulldata/tld.cert"
	common.StoreCertificatePEM(tld_cert_path, tld_cert)

	tld_config := parent.Config{
		Zone:                 tld_zone,
		AuthenticationType:   "certificate",
		LogCheckerExtAddress: CHECKER_ADDRESS,
		PrivateKeyAlgorithm:  tld_alg,
		PrivateKeyPath:       tld_key_path,
		CertificatePath:      tld_cert_path,
		CAAddress:            CA_ADDRESS,
		OutputDir:            "testfulldata/",
	}

	tld_conf_file, _ := json.MarshalIndent(tld_config, "", " ")
	_ = ioutil.WriteFile("testfulldata/tld.conf", tld_conf_file, 0644)

	//TLD := parent.NewParent(tld_config)




}