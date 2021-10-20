package psb

import (
	"crypto/rsa"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// SMU off chip firmware signing key information
var N = "971472917905694235859527690907502923402301948031921241171273698806712501341143764872164817936205323093673268936716169271014956780829744939605805336378355604317689589643879933296619769853977997537504409513857548495835554760316169706145871580241299859391727532123062316131763291333497897666085493912196453830838835409116482525805019707393297818644968410993413227674593522445365251216146843534545538446317137254095278019564256619548518070446087126473960778214502148894932879929259282158773739433517309889480032232186219446391610435919379779378252560032397509979809202392043110002380553502817271070140095904800150060054898411959116413989750574319580379588063907374731560190664369153626299598002608484164204182073967364520170387618360414494928968064669008506200599321614764379343663974785424808230448954042498800415697272404985468748776993396194504501173460207698442122815473122167399338113883863561341937240713815386295760840924504030444583243381824402019007306020777513381800531855947355754646526659806863711949295870720607069380951550984974668335178048036250641301510976999844724811954772642716092471925323531085871838421575832526959241303117218657087055880924069551198635498158413029865582648473844773084423426422930595846516126856911"

type PsbBinarySuite struct {
	suite.Suite
}

func (suite *PsbBinarySuite) TestPSBBinaryIsParsedCorrectly() {
	psbBinary, err := newPSPBinary(smuOffChipFirmware)
	assert.NoError(suite.T(), err)

	hdr := psbBinary.Header()
	assert.Equal(suite.T(), uint32(0x31535024), hdr.Version())
}

func (suite *PsbBinarySuite) TestPSBBinarySignedData() {
	// we are using SMU off-chip firmware for testing PSB binary control
	// paths and we need the corresponding signing key, which is contained
	// in the key database. We could just extract the single key from the
	// database, but it's easier to parse the database as a whole
	keySet := NewKeySet()
	err := parseKeyDatabase(keyDB, keySet)
	assert.NoError(suite.T(), err)

	psbBinary, err := newPSPBinary(smuOffChipFirmware)
	assert.NoError(suite.T(), err)

	blob, err := psbBinary.getSignedBlob(keySet)
	assert.NoError(suite.T(), err)
	// verify that the signed data matches the content of the blob, excluding the final signature
	assert.Equal(suite.T(), smuOffChipFirmware[:len(smuOffChipFirmware)-512], blob.SignedData())

	sig := blob.Signature()
	assert.NotNil(suite.T(), sig)
	key := sig.SigningKey()
	assert.NotNil(suite.T(), key)
	keyID := key.KeyID()
	assert.Equal(suite.T(), hex.EncodeToString(smuSigningKeyID[:]), keyID.String())

	// obtain the RSA key from the generic Key object
	pubKey, err := key.Get()
	assert.NoError(suite.T(), err)
	rsaKey := pubKey.(*rsa.PublicKey)
	assert.NotNil(suite.T(), rsaKey)

	n := big.Int{}
	n.SetString(N, 10)
	assert.Equal(suite.T(), n, *rsaKey.N)
	assert.Equal(suite.T(), int(65537), rsaKey.E)

}

func TestPsbBinarySuite(t *testing.T) {
	suite.Run(t, new(PsbBinarySuite))
}
