package btcmultisig

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	SigHashOld          = txscript.SigHashOld
	SigHashAll          = txscript.SigHashAll
	SigHashNone         = txscript.SigHashNone
	SigHashSingle       = txscript.SigHashSingle
	SigHashAnyOneCanPay = txscript.SigHashAnyOneCanPay
)

type SpendFromMultiSigTransaction struct {
	baseTX      *wire.MsgTx
	Address     *MultiSigAddress
	signedCount map[string][][]byte
}

func NewSpendFromMultiSigTransactionWithUtxoSelection(multisigAddress *MultiSigAddress, utxos []UTXO, outputs []Output) (*SpendFromMultiSigTransaction, error) {
	utxosSelected := selectUtxos(utxos, outputs)
	return NewSpendFromMultiSigTransaction(multisigAddress, utxosSelected, outputs)

}
func NewSpendFromMultiSigTransaction(multisigAddress *MultiSigAddress, utxos []UTXO, outputs []Output) (*SpendFromMultiSigTransaction, error) {
	if balance(utxos) < totalInOutputSet(outputs) {
		return nil, errors.New("not enough balance to create the transaction")
	}

	msgtx := wire.NewMsgTx(wire.TxVersion)
	//Inputs

	//Get the utxos and put in the tranaction
	for _, x := range utxos {
		utxoHash, err := chainhash.NewHashFromStr(x.Hash)
		if err != nil {
			return nil, fmt.Errorf("unexpected utxo hash: %s", utxoHash)
		}
		input := wire.NewOutPoint(utxoHash, uint32(x.Vout))

		//Put the input in the transaction
		msgtx.AddTxIn(wire.NewTxIn(input, nil, nil))
	}

	//Outputs
	for _, x := range outputs {
		addressDecoded, err := btcutil.DecodeAddress(x.Address, multisigAddress.Network)
		if err != nil {
			return nil, fmt.Errorf("unexpected destination address: %s", x.Address)
		}
		addrBytes, err := txscript.PayToAddrScript(addressDecoded)
		if err != nil {
			return nil, err
		}
		output := wire.NewTxOut(amountInSats(x.Amount), addrBytes)

		//Put the output in the transaction
		msgtx.AddTxOut(output)
	}
	tx := &SpendFromMultiSigTransaction{
		baseTX:  msgtx,
		Address: multisigAddress,
	}
	tx.signedCount = make(map[string][][]byte)
	tx.setPubKeys()
	return tx, nil

}

func (tx *SpendFromMultiSigTransaction) SignWithWIF(WIF string, sigType txscript.SigHashType) error {
	wif, err := btcutil.DecodeWIF(WIF)
	if err != nil {
		return err
	}
	privkey := wif.PrivKey
	return tx.sign(privkey, sigType)
}

func (tx *SpendFromMultiSigTransaction) sign(privkey *btcec.PrivateKey, sigType txscript.SigHashType) error {
	pubkey := privkey.PubKey()
	err := tx.isSigned(pubkey)
	if err != nil {
		return err
	}
	tx.signedCount[pubkey.X().String()] = make([][]byte, len(tx.baseTX.TxIn))

	for i := range tx.baseTX.TxIn {
		signature, err := txscript.RawTxInSignature(tx.baseTX, i, tx.Address.redeemScript, txscript.SigHashType(sigType), privkey)
		if err != nil {
			return err
		}
		tx.signedCount[pubkey.X().String()][i] = signature
	}
	return nil
}

func (tx *SpendFromMultiSigTransaction) Sign(privKey string, sigType txscript.SigHashType) error {
	pkBytes, err := hex.DecodeString(privKey)
	if err != nil {
		return err
	}
	privkey, _ := btcec.PrivKeyFromBytes(pkBytes)
	return tx.sign(privkey, sigType)

}

/*
func (tx *SpendFromMultiSigTransaction) signSingleInput(inputIndex int, WIF string, sigType txscript.SigHashType) error {
	if inputIndex <= 0 || inputIndex >= len(tx.baseTX.TxIn) {
		return errors.New("ivalid input index")
	}
	wif, err := btcutil.DecodeWIF(WIF)
	if err != nil {
		return err
	}
	privkey := wif.PrivKey

	pubkey := privkey.PubKey()
	err = tx.isSigned(pubkey)
	if err != nil {
		return err
	}
	sig1, err := txscript.RawTxInSignature(tx.baseTX, inputIndex, tx.Address.redeemScript, txscript.SigHashType(sigType), privkey)
	if err != nil {
		return err
	}
	tx.signedCount[pubkey.X.String()][inputIndex] = sig1
	return nil
}
*/

func (tx *SpendFromMultiSigTransaction) BuildScript() error {
	if tx.NumberOfSignaturesProvided() < tx.Address.signaturesRequired {
		return fmt.Errorf("missing signatures, got %d of %d required", tx.NumberOfSignaturesProvided(), tx.Address.signaturesRequired)
	}
	for _, x := range tx.signedCount {
		for input := range x {
			err := tx.buildRespectiveInputScript(input)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (tx *SpendFromMultiSigTransaction) buildRespectiveInputScript(inputIndex int) error {
	if tx.NumberOfSignaturesProvided() < tx.Address.signaturesRequired {
		return fmt.Errorf("missing signatures, got %d of %d required", tx.NumberOfSignaturesProvided(), tx.Address.signaturesRequired)
	}
	if inputIndex < 0 || inputIndex >= len(tx.baseTX.TxIn) {
		return errors.New("ivalid input index")
	}
	scriptBuilder := txscript.NewScriptBuilder()
	scriptBuilder.AddOp(txscript.OP_FALSE)

	for _, x := range tx.signedCount {
		if x != nil {
			scriptBuilder.AddData(x[inputIndex])
		}
	}
	scriptBuilder.AddData(tx.Address.redeemScript)
	signatureSRC, err := scriptBuilder.Script()
	if err != nil {
		return err
	}
	tx.baseTX.TxIn[inputIndex].SignatureScript = signatureSRC
	return nil
}

func (tx *SpendFromMultiSigTransaction) Serialize() string {
	var buffer bytes.Buffer
	tx.baseTX.Serialize(&buffer)
	return hex.EncodeToString(buffer.Bytes())
}

func (tx *SpendFromMultiSigTransaction) NumberOfSignaturesProvided() (count int) {
	for _, y := range tx.signedCount {
		if y != nil {
			count++
		}
	}
	return
}

//Sort the utxo set and return the smallest set of txs that satisfy the spend
func selectUtxos(unspentInputs []UTXO, outputs []Output) (utxoSelection []UTXO) {
	//Get  the total output value
	totalToSend := totalInOutputSet(outputs)

	//sort the utxos
	sort.Slice(unspentInputs, func(i, j int) bool {
		return unspentInputs[i].Amount > unspentInputs[j].Amount
	})

	//How many utxos will selected from the sorted set
	var sum float64

	//select the utxos to satisfy the output amount
	for i, x := range unspentInputs {
		sum += x.Amount
		if sum > totalToSend {
			utxoSelection = unspentInputs[:i]
			return
		}
	}

	//if the utxo set is not enough to satisfy the output, an empty slice is returned
	return
}

func totalInOutputSet(outputs []Output) (total float64) {
	for _, x := range outputs {
		total += x.Amount
	}
	return total
}

func balance(utxos []UTXO) (total float64) {
	for _, x := range utxos {
		total += x.Amount
	}
	return total
}

func amountInSats(amount float64) int64 {
	return int64(amount * 100000000)
}

//initialize the map that will manage the requiredSigns
func (tx *SpendFromMultiSigTransaction) setPubKeys() {
	for _, x := range tx.Address.publicKeys {
		tx.signedCount[x.X().String()] = nil
	}
}

//check if the transaction has the respective signature for a given pubkey
func (tx *SpendFromMultiSigTransaction) isSigned(pubKey *btcec.PublicKey) (err error) {
	//Check is the pubkey is part of the multisigAddress Logic
	for x, y := range tx.signedCount {
		if x == pubKey.X().String() {
			//if the signature has not been yet provided
			if y == nil {
				return nil
			}
			//the signature is already in the transaction
			return errors.New("the transaction has already been signed with that private key")
		}
	}
	//the multisig address doestn have the pubkey in its definition
	return errors.New("the privkey provided is not valid for this transaction")
}

/*

func (tx *SpendFromMultiSigTransaction) checkIfAllInputsAreSigned() bool {
	firstPubKeyCountNumber := 0
	for _, x := range tx.signedCount {
		if firstPubKeyCountNumber != 0 && firstPubKeyCountNumber != len(x) {
			return false
		}
		firstPubKeyCountNumber = len(x)

	}
	return true
}
*/
