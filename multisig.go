package btcmultisig

import (
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

type MultiSigAddress struct {
	//each pubkey is represent as []byte
	publicKeys          []btcec.PublicKey
	signaturesRequired  int
	redeemScript        []byte
	redeemHash          []byte
	address             *btcutil.AddressScriptHash
	AddressEncoded      string
	RedeemScriptEncoded string
	Network             *chaincfg.Params
}

func NewMultiSigAddress(net *chaincfg.Params, signaturesRequired int, strPubKeys ...string) (*MultiSigAddress, error) {
	if signaturesRequired > len(strPubKeys) {
		return nil, errors.New("signaturesRequired moust be <= pubkeys length")
	}
	if signaturesRequired <= 0 {
		return nil, errors.New("invalid signaturesRequired parameter")
	}
	if len(strPubKeys) <= 0 || len(strPubKeys) > 16 {
		return nil, errors.New("invalid number of pubkeys")
	}
	pubKey, err := getPubKeys(strPubKeys...)
	if err != nil {
		return nil, err
	}

	addr := &MultiSigAddress{
		signaturesRequired: signaturesRequired,
		publicKeys:         pubKey,
		Network:            net,
	}
	err = addr.buildRedeemScript()
	if err != nil {
		return nil, err
	}
	addr.address, err = btcutil.NewAddressScriptHashFromHash(addr.redeemHash, net)
	if err != nil {
		return nil, err
	}
	addr.AddressEncoded = addr.address.EncodeAddress()
	addr.RedeemScriptEncoded, err = txscript.DisasmString(addr.redeemScript)
	if err != nil {
		return nil, err
	}
	return addr, nil

}

func (addr *MultiSigAddress) buildRedeemScript() error {
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_2)
	for _, x := range addr.publicKeys {
		builder.AddData(x.SerializeCompressed())
	}
	builder.AddOp(txscript.OP_3)
	builder.AddOp(txscript.OP_CHECKMULTISIG)
	redeemScript, err := builder.Script()
	if err != nil {
		return err
	}
	addr.redeemScript = redeemScript
	addr.redeemHash = btcutil.Hash160(redeemScript)
	return nil
}

func getPubKeys(strPubKeys ...string) (pubKeys []btcec.PublicKey, err error) {
	for _, x := range strPubKeys {
		pubKeyBytes, err := hex.DecodeString(x)
		if err != nil {
			return nil, err
		}
		pubKey, err := btcec.ParsePubKey(pubKeyBytes)
		if err != nil {
			return nil, err
		}
		pubKeys = append(pubKeys, *pubKey)
	}
	return
}
