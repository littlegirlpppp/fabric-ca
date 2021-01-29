package decrypter

import (
	"crypto"
	"io"

	"github.com/pkg/errors"
	"github.com/tw-bc-group/fabric-gm/bccsp"
	"github.com/tw-bc-group/fabric-gm/bccsp/utils"
)

type bccspDecrypter struct {
	csp bccsp.BCCSP
	key bccsp.Key
	pk  interface{}
}

func New(csp bccsp.BCCSP, key bccsp.Key) (crypto.Decrypter, error) {
	// Validate arguments
	if csp == nil {
		return nil, errors.New("bccsp instance must be different from nil.")
	}
	if key == nil {
		return nil, errors.New("key must be different from nil.")
	}
	if key.Symmetric() {
		return nil, errors.New("key must be asymmetric.")
	}

	// Marshall the bccsp public key as a crypto.PublicKey
	pub, err := key.PublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed getting public key")
	}

	raw, err := pub.Bytes()
	if err != nil {
		return nil, errors.Wrap(err, "failed marshalling public key")
	}

	pk, err := utils.DERToPublicKey(raw)
	if err != nil {
		return nil, errors.Wrap(err, "failed marshalling der to public key")
	}

	return &bccspDecrypter{csp, key, pk}, nil
}

func (s *bccspDecrypter) Public() crypto.PublicKey {
	return s.pk
}

func (s *bccspDecrypter) Decrypt(_ io.Reader, cipher []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	return s.csp.Decrypt(s.key, cipher, opts)
}

