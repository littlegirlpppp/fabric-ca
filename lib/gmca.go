package lib

import (
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"time"

	"github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"

	"crypto"
	"crypto/rand"
	"encoding/pem"
	"io"
	"math/big"

	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	x509GM "github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/tw-bc-group/fabric-gm/bccsp"
	"github.com/tw-bc-group/fabric-gm/bccsp/gm"

	"github.com/cloudflare/cfssl/signer"
	"github.com/tw-bc-group/fabric-ca-gm/util"
)

// add by thoughtwork's matrix
func OverrideHosts(template *x509GM.Certificate, hosts []string) {
	if hosts != nil {
		template.IPAddresses = []net.IP{}
		template.EmailAddresses = []string{}
		template.DNSNames = []string{}
	}

	for i := range hosts {
		if ip := net.ParseIP(hosts[i]); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(hosts[i]); err == nil && email != nil {
			template.EmailAddresses = append(template.EmailAddresses, email.Address)
		} else {
			template.DNSNames = append(template.DNSNames, hosts[i])
		}
	}
}

// replaceSliceIfEmpty replaces the contents of replaced with newContents if
// the slice referenced by replaced is empty
func replaceSliceIfEmpty(replaced, newContents *[]string) {
	if len(*replaced) == 0 {
		*replaced = *newContents
	}
}

// PopulateSubjectFromCSR has functionality similar to Name, except
// it fills the fields of the resulting pkix.Name with req's if the
// subject's corresponding fields are empty
func PopulateSubjectFromCSR(s *signer.Subject, req pkix.Name) pkix.Name {
	// if no subject, use req
	if s == nil {
		return req
	}
	name := s.Name()

	if name.CommonName == "" {
		name.CommonName = req.CommonName
	}

	replaceSliceIfEmpty(&name.Country, &req.Country)
	replaceSliceIfEmpty(&name.Province, &req.Province)
	replaceSliceIfEmpty(&name.Locality, &req.Locality)
	replaceSliceIfEmpty(&name.Organization, &req.Organization)
	replaceSliceIfEmpty(&name.OrganizationalUnit, &req.OrganizationalUnit)
	if name.SerialNumber == "" {
		name.SerialNumber = req.SerialNumber
	}
	return name
}

//证书签名
func signCert(req signer.SignRequest, ca *CA) (cert []byte, err error) {
	block, _ := pem.Decode([]byte(req.Request))
	if block == nil {
		return nil, fmt.Errorf("decode error")
	}
	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("not a csr")
	}
	template, err := parseCertificateRequest(block.Bytes)
	if err != nil {
		log.Infof("xxxx gmca.go ParseCertificateRequest error:[%s]", err)
		return nil, err
	}

	certfile := ca.Config.CA.Certfile
	//certfile := req.Profile
	log.Infof("^^^^^^^^^^^^^^^^^^^^^^^certifle = %s", certfile)
	_, rootSigner, x509cert, err := util.GetSignerFromCertFile(certfile, ca.csp)
	if err != nil {

		return nil, err
	}
	log.Infof("^^^^^^^^^^^^^^^^^^^^^^^x509cert = %v", x509cert)
	rootca := ParseX509Certificate2Sm2(x509cert)

	// add by thoughtwork's matrix
	// override the ou with role
	OverrideHosts(template, req.Hosts)
	template.Subject = PopulateSubjectFromCSR(req.Subject, template.Subject)
	profile, err := FindProfile(ca.enrollSigner.Policy(), req.Profile)
	if err != nil {
		return nil, err
	}

	err = FillTemplate(template, ca.enrollSigner.Policy().Default, profile, template.NotBefore, template.NotAfter)
	if err != nil {
		return nil, err
	}



	cert, err = gm.CreateCertificateToMem(template, rootca, rootSigner)
	if err != nil {
		return nil, err
	}
	log.Infof("^^^^^^^^^^^^^^^^^^^^^^^template = %v\n cert = %v\n Type = %T", template, cert, template.PublicKey)
	clientCert, err := x509GM.ReadCertificateFromPem(cert)
	log.Info("==================== Exit ParseCertificate")
	if err == nil {
		log.Infof("xxxx gmca.go signCert ok the sign cert len [%d]", len(cert))
	} else {
		return nil, err
	}

	var certRecord = certdb.CertificateRecord{
		Serial:  clientCert.SerialNumber.String(),
		AKI:     hex.EncodeToString(clientCert.AuthorityKeyId),
		CALabel: req.Label,
		Status:  "good",
		Expiry:  clientCert.NotAfter,
		PEM:     string(cert),
	}
	//aki := hex.EncodeToString(cert.AuthorityKeyId)
	//serial := util.GetSerialAsHex(cert.SerialNumber)
	err = ca.certDBAccessor.InsertCertificate(certRecord)
	return
}

// CAPolicy contains the CA issuing policy as default policy.
var CAPolicy = func() *config.Signing {
	return &config.Signing{
		Default: &config.SigningProfile{
			Usage:        []string{"cert sign", "crl sign"},
			ExpiryString: "43800h",
			Expiry:       5 * helpers.OneYear,
			CAConstraint: config.CAConstraint{IsCA: true},
		},
	}
}

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func ComputeSKI(template *x509GM.Certificate) ([]byte, error) {
	pub := template.PublicKey
	encodedPub, err := x509GM.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	var subPKI subjectPublicKeyInfo
	_, err = asn1.Unmarshal(encodedPub, &subPKI)
	if err != nil {
		return nil, err
	}

	pubHash := sha1.Sum(subPKI.SubjectPublicKey.Bytes)
	return pubHash[:], nil
}

type policyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
	Qualifiers       []interface{} `asn1:"tag:optional,omitempty"`
}

type cpsPolicyQualifier struct {
	PolicyQualifierID asn1.ObjectIdentifier
	Qualifier         string `asn1:"tag:optional,ia5"`
}

type userNotice struct {
	ExplicitText string `asn1:"tag:optional,utf8"`
}
type userNoticePolicyQualifier struct {
	PolicyQualifierID asn1.ObjectIdentifier
	Qualifier         userNotice
}

var (
	// Per https://tools.ietf.org/html/rfc3280.html#page-106, this represents:
	// iso(1) identified-organization(3) dod(6) internet(1) security(5)
	//   mechanisms(5) pkix(7) id-qt(2) id-qt-cps(1)
	iDQTCertificationPracticeStatement = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}
	// iso(1) identified-organization(3) dod(6) internet(1) security(5)
	//   mechanisms(5) pkix(7) id-qt(2) id-qt-unotice(2)
	iDQTUserNotice = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}

	// CTPoisonOID is the object ID of the critical poison extension for precertificates
	// https://tools.ietf.org/html/rfc6962#page-9
	CTPoisonOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

	// SCTListOID is the object ID for the Signed Certificate Timestamp certificate extension
	// https://tools.ietf.org/html/rfc6962#page-14
	SCTListOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

func addPolicies(template *x509GM.Certificate, policies []config.CertificatePolicy) error {
	var asn1PolicyList []policyInformation

	for _, policy := range policies {
		pi := policyInformation{
			// The PolicyIdentifier is an OID assigned to a given issuer.
			PolicyIdentifier: asn1.ObjectIdentifier(policy.ID),
		}
		for _, qualifier := range policy.Qualifiers {
			switch qualifier.Type {
			case "id-qt-unotice":
				pi.Qualifiers = append(pi.Qualifiers,
					userNoticePolicyQualifier{
						PolicyQualifierID: iDQTUserNotice,
						Qualifier: userNotice{
							ExplicitText: qualifier.Value,
						},
					})
			case "id-qt-cps":
				pi.Qualifiers = append(pi.Qualifiers,
					cpsPolicyQualifier{
						PolicyQualifierID: iDQTCertificationPracticeStatement,
						Qualifier:         qualifier.Value,
					})
			default:
				return errors.New("Invalid qualifier type in Policies " + qualifier.Type)
			}
		}
		asn1PolicyList = append(asn1PolicyList, pi)
	}

	asn1Bytes, err := asn1.Marshal(asn1PolicyList)
	if err != nil {
		return err
	}

	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 32},
		Critical: false,
		Value:    asn1Bytes,
	})
	return nil
}

func FillTemplate(template *x509GM.Certificate, defaultProfile, profile *config.SigningProfile, notBefore time.Time, notAfter time.Time) error {
	ski, err := ComputeSKI(template)
	if err != nil {
		return err
	}

	var (
		eku             []x509.ExtKeyUsage
		ku              x509.KeyUsage
		backdate        time.Duration
		expiry          time.Duration
		crlURL, ocspURL string
		issuerURL       = profile.IssuerURL
	)

	// The third value returned from Usages is a list of unknown key usages.
	// This should be used when validating the profile at load, and isn't used
	// here.
	ku, eku, _ = profile.Usages()
	sm2eku := make([]x509GM.ExtKeyUsage, len(eku))

	for i := 0; i < len(eku); i++ {
		sm2eku[i] = x509GM.ExtKeyUsage(eku[i])
	}

	if profile.IssuerURL == nil {
		issuerURL = defaultProfile.IssuerURL
	}

	if ku == 0 && len(eku) == 0 {
		return cferr.New(cferr.PolicyError, cferr.NoKeyUsages)
	}

	if expiry = profile.Expiry; expiry == 0 {
		expiry = defaultProfile.Expiry
	}

	if crlURL = profile.CRL; crlURL == "" {
		crlURL = defaultProfile.CRL
	}
	if ocspURL = profile.OCSP; ocspURL == "" {
		ocspURL = defaultProfile.OCSP
	}

	if notBefore.IsZero() {
		if !profile.NotBefore.IsZero() {
			notBefore = profile.NotBefore
		} else {
			if backdate = profile.Backdate; backdate == 0 {
				backdate = -5 * time.Minute
			} else {
				backdate = -1 * profile.Backdate
			}
			notBefore = time.Now().Round(time.Minute).Add(backdate)
		}
	}
	notBefore = notBefore.UTC()

	if notAfter.IsZero() {
		if !profile.NotAfter.IsZero() {
			notAfter = profile.NotAfter
		} else {
			notAfter = notBefore.Add(expiry)
		}
	}
	notAfter = notAfter.UTC()

	template.NotBefore = notBefore
	template.NotAfter = notAfter
	template.KeyUsage = x509GM.KeyUsage(ku)
	template.ExtKeyUsage = sm2eku
	template.BasicConstraintsValid = true
	template.IsCA = profile.CAConstraint.IsCA
	if template.IsCA {
		template.MaxPathLen = profile.CAConstraint.MaxPathLen
		if template.MaxPathLen == 0 {
			template.MaxPathLenZero = profile.CAConstraint.MaxPathLenZero
		}
		template.DNSNames = nil
		template.EmailAddresses = nil
	}
	template.SubjectKeyId = ski

	if ocspURL != "" {
		template.OCSPServer = []string{ocspURL}
	}
	if crlURL != "" {
		template.CRLDistributionPoints = []string{crlURL}
	}

	if len(issuerURL) != 0 {
		template.IssuingCertificateURL = issuerURL
	}
	if len(profile.Policies) != 0 {
		err = addPolicies(template, profile.Policies)
		if err != nil {
			return cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy, err)
		}
	}
	if profile.OCSPNoCheck {
		ocspNoCheckExtension := pkix.Extension{
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
			Critical: false,
			Value:    []byte{0x05, 0x00},
		}
		template.ExtraExtensions = append(template.ExtraExtensions, ocspNoCheckExtension)
	}

	return nil
}

func FindProfile(policy *config.Signing, profile string) (*config.SigningProfile, error) {
	var p *config.SigningProfile
	if policy != nil && policy.Profiles != nil && profile != "" {
		p = policy.Profiles[profile]
	}

	if p == nil && policy != nil {
		p = policy.Default
	}

	if p == nil {
		return nil, cferr.Wrap(cferr.APIClientError, cferr.ClientHTTPError, errors.New("profile must not be nil"))
	}
	return p, nil
}

//生成证书
func createGmSm2Cert(key bccsp.Key, req *csr.CertificateRequest, signer crypto.Signer) (cert []byte, err error) {
	log.Infof("xxx xxx in gmca.go  createGmSm2Cert...key :%T", key)

	policy := CAPolicy()
	if req.CA != nil {
		if req.CA.Expiry != "" {
			policy.Default.ExpiryString = req.CA.Expiry
			policy.Default.Expiry, err = time.ParseDuration(req.CA.Expiry)
			if err != nil {
				return nil, err
			}
		}

		policy.Default.CAConstraint.MaxPathLen = req.CA.PathLength
		if req.CA.PathLength != 0 && req.CA.PathLenZero == true {
			log.Infof("ignore invalid 'pathlenzero' value")
		} else {
			policy.Default.CAConstraint.MaxPathLenZero = req.CA.PathLenZero
		}
	}

	if !policy.Valid() {
		return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy)
	}

	csrPEM, err := generate(signer, req)
	if err != nil {
		log.Infof("xxxxxxxxxxxxx create csr error:%s", err)
	}
	log.Infof("xxxxxxxxxxxxx create gm csr completed!")
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("sm2 csr DecodeFailed")
	}

	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("sm2 not a csr")
	}
	sm2Template, err := parseCertificateRequest(block.Bytes)
	if err != nil {
		log.Infof("parseCertificateRequest return err:%s", err)
		return nil, err
	}

	err = FillTemplate(sm2Template, policy.Default, policy.Default, time.Time{}, time.Time{})
	if err != nil {
		return nil, err
	}

	sm2Template.SubjectKeyId = key.SKI()
	log.Infof("key is %T   ---%T", sm2Template.PublicKey, sm2Template)
	cert, err = gm.CreateCertificateToMem(sm2Template, sm2Template, signer)
	return cert, err
}

//证书请求转换成证书  参数为  block .Bytes
func parseCertificateRequest(csrBytes []byte) (template *x509GM.Certificate, err error) {
	csrv, err := x509GM.ParseCertificateRequest(csrBytes)
	if err != nil {
		//err = cferr.Wrap(cferr.CSRError, cferr.ParseFailed, err)
		return
	}
	err = csrv.CheckSignature()
	// if err != nil {
	// 	//err = cferr.Wrap(cferr.CSRError, cferr.KeyMismatch, err)
	// 	return
	// }
	template = &x509GM.Certificate{
		Subject:            csrv.Subject,
		PublicKeyAlgorithm: csrv.PublicKeyAlgorithm,
		PublicKey:          csrv.PublicKey,
		SignatureAlgorithm: csrv.SignatureAlgorithm,
		DNSNames:           csrv.DNSNames,
		IPAddresses:        csrv.IPAddresses,
		EmailAddresses:     csrv.EmailAddresses,
	}

	fmt.Printf("^^^^^^^^^^^^^^^^^^^^^^^^^^algorithn = %v, %v\n", template.PublicKeyAlgorithm, template.SignatureAlgorithm)
	log.Infof("xxxx publicKey :%T", template.PublicKey)

	template.NotBefore = time.Now()
	template.NotAfter = time.Now().Add(time.Hour * 1000)
	//log.Infof("-----------csrv = %+v", csrv)
	for _, val := range csrv.Extensions {
		// Check the CSR for the X.509 BasicConstraints (RFC 5280, 4.2.1.9)
		// extension and append to template if necessary
		if val.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}) {
			var constraints csr.BasicConstraints
			var rest []byte

			if rest, err = asn1.Unmarshal(val.Value, &constraints); err != nil {
				//return nil, cferr.Wrap(cferr.CSRError, cferr.ParseFailed, err)
			} else if len(rest) != 0 {
				//return nil, cferr.Wrap(cferr.CSRError, cferr.ParseFailed, errors.New("x509: trailing data after X.509 BasicConstraints"))
			}

			template.BasicConstraintsValid = true
			template.IsCA = constraints.IsCA
			template.MaxPathLen = constraints.MaxPathLen
			template.MaxPathLenZero = template.MaxPathLen == 0
		}
	}
	serialNumber := make([]byte, 20)
	_, err = io.ReadFull(rand.Reader, serialNumber)
	if err != nil {
		return nil, err
	}

	// SetBytes interprets buf as the bytes of a big-endian
	// unsigned integer. The leading byte should be masked
	// off to ensure it isn't negative.
	serialNumber[0] &= 0x7F

	template.SerialNumber = new(big.Int).SetBytes(serialNumber)

	return
}

//cloudflare 证书请求 转成 国密证书请求
func generate(priv crypto.Signer, req *csr.CertificateRequest) (csr []byte, err error) {
	log.Info("xx entry gm generate")
	sigAlgo := signerAlgo(priv)
	if sigAlgo == x509GM.UnknownSignatureAlgorithm {
		return nil, fmt.Errorf("Private key is unavailable")
	}
	log.Info("xx begin create sm2.CertificateRequest")
	var tpl = x509GM.CertificateRequest{
		Subject:            req.Name(),
		SignatureAlgorithm: sigAlgo,
	}
	for i := range req.Hosts {
		if ip := net.ParseIP(req.Hosts[i]); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(req.Hosts[i]); err == nil && email != nil {
			tpl.EmailAddresses = append(tpl.EmailAddresses, email.Address)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, req.Hosts[i])
		}
	}

	if req.CA != nil {
		err = appendCAInfoToCSRSm2(req.CA, &tpl)
		if err != nil {
			err = fmt.Errorf("sm2 GenerationFailed")
			return
		}
	}
	if req.SerialNumber != "" {

	}
	csr, err = gm.CreateSm2CertificateRequestToMem(&tpl, priv)
	log.Info("xx exit generate")
	return csr, err
}

func signerAlgo(priv crypto.Signer) x509GM.SignatureAlgorithm {
	switch pub := priv.Public().(type) {
	case *sm2.PublicKey:
		switch pub.Curve {
		case sm2.P256Sm2():
			return x509GM.SM2WithSM3
		default:
			return x509GM.SM2WithSM3
		}
	default:
		return x509GM.UnknownSignatureAlgorithm
	}
}

// appendCAInfoToCSR appends CAConfig BasicConstraint extension to a CSR
func appendCAInfoToCSR(reqConf *csr.CAConfig, csreq *x509.CertificateRequest) error {
	pathlen := reqConf.PathLength
	if pathlen == 0 && !reqConf.PathLenZero {
		pathlen = -1
	}
	val, err := asn1.Marshal(csr.BasicConstraints{true, pathlen})

	if err != nil {
		return err
	}

	csreq.ExtraExtensions = []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
			Value:    val,
			Critical: true,
		},
	}
	return nil
}

// appendCAInfoToCSR appends CAConfig BasicConstraint extension to a CSR
func appendCAInfoToCSRSm2(reqConf *csr.CAConfig, csreq *x509GM.CertificateRequest) error {
	pathlen := reqConf.PathLength
	if pathlen == 0 && !reqConf.PathLenZero {
		pathlen = -1
	}
	val, err := asn1.Marshal(csr.BasicConstraints{true, pathlen})

	if err != nil {
		return err
	}

	csreq.ExtraExtensions = []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
			Value:    val,
			Critical: true,
		},
	}

	return nil
}

func ParseX509Certificate2Sm2(x509Cert *x509.Certificate) *x509GM.Certificate {
	sm2cert := &x509GM.Certificate{
		Raw:                         x509Cert.Raw,
		RawTBSCertificate:           x509Cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo:     x509Cert.RawSubjectPublicKeyInfo,
		RawSubject:                  x509Cert.RawSubject,
		RawIssuer:                   x509Cert.RawIssuer,
		Signature:                   x509Cert.Signature,
		SignatureAlgorithm:          x509GM.SignatureAlgorithm(x509Cert.SignatureAlgorithm),
		PublicKeyAlgorithm:          x509GM.PublicKeyAlgorithm(x509Cert.PublicKeyAlgorithm),
		PublicKey:                   x509Cert.PublicKey,
		Version:                     x509Cert.Version,
		SerialNumber:                x509Cert.SerialNumber,
		Issuer:                      x509Cert.Issuer,
		Subject:                     x509Cert.Subject,
		NotBefore:                   x509Cert.NotBefore,
		NotAfter:                    x509Cert.NotAfter,
		KeyUsage:                    x509GM.KeyUsage(x509Cert.KeyUsage),
		Extensions:                  x509Cert.Extensions,
		ExtraExtensions:             x509Cert.ExtraExtensions,
		UnhandledCriticalExtensions: x509Cert.UnhandledCriticalExtensions,
		//ExtKeyUsage:	[]x509.ExtKeyUsage(x509Cert.ExtKeyUsage) ,
		UnknownExtKeyUsage:    x509Cert.UnknownExtKeyUsage,
		BasicConstraintsValid: x509Cert.BasicConstraintsValid,
		IsCA:                  x509Cert.IsCA,
		MaxPathLen:            x509Cert.MaxPathLen,
		// MaxPathLenZero indicates that BasicConstraintsValid==true and
		// MaxPathLen==0 should be interpreted as an actual maximum path length
		// of zero. Otherwise, that combination is interpreted as MaxPathLen
		// not being set.
		MaxPathLenZero: x509Cert.MaxPathLenZero,
		SubjectKeyId:   x509Cert.SubjectKeyId,
		AuthorityKeyId: x509Cert.AuthorityKeyId,
		// RFC 5280, 4.2.2.1 (Authority Information Access)
		OCSPServer:            x509Cert.OCSPServer,
		IssuingCertificateURL: x509Cert.IssuingCertificateURL,
		// Subject Alternate Name values
		DNSNames:       x509Cert.DNSNames,
		EmailAddresses: x509Cert.EmailAddresses,
		IPAddresses:    x509Cert.IPAddresses,
		// Name constraints
		PermittedDNSDomainsCritical: x509Cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         x509Cert.PermittedDNSDomains,
		// CRL Distribution Points
		CRLDistributionPoints: x509Cert.CRLDistributionPoints,
		PolicyIdentifiers:     x509Cert.PolicyIdentifiers,
	}
	for _, val := range x509Cert.ExtKeyUsage {
		sm2cert.ExtKeyUsage = append(sm2cert.ExtKeyUsage, x509GM.ExtKeyUsage(val))
	}
	return sm2cert
}
