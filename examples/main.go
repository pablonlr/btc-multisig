package main

import (
	"encoding/hex"
	"fmt"

	multisig "github.com/pablonlr/btc-multisig"

	"github.com/btcsuite/btcd/btcutil"
)

func main() {
	//We have a raw pubkey1 and we know its privkey. It is easy to derivate the pubkey from the Privkey.
	privKey1 := "9a7026f99a0452991d675cad5cf8ec4a1cba046cbc67f41f8b9fccdd993328a8"
	pubKey1 := "0234bb639abd8f8a108013674a6d90582189afd06fc529147a854ec4dc43565e4f"

	//A WIF compressed to obtain pubKey2
	wif2String := "cTG4L8A7QAr5FyhwW2sYg35ydGLTs8o19ypnBoNhzubKdLpwBZBN"

	//A rawPubKey that we not necessary know its privkey
	pubKey3 := "022f07d5d42600587f01c9fd432a2ece38a66e7f56789e98fb11507d1a70efddf2"

	//Now lets derivate the PubKey2 from the WIF
	wif2, err := btcutil.DecodeWIF(wif2String)
	if err != nil {
		panic(err)
	}
	pubKey2Bytes := wif2.SerializePubKey()

	//Encode the bytes pubkey to a string representation
	pubKey2 := hex.EncodeToString(pubKey2Bytes)

	//Nice we have pubKey1, pubKey2 and pubKey3, lets create our multisig address:
	addr, err := multisig.NewMultiSigAddress(multisig.BTC_TESNET, 2, pubKey1, pubKey2, pubKey3)
	if err != nil {
		panic(err)
	}

	// print our multisig encoded address:
	fmt.Printf("Address: %s\n", addr.AddressEncoded)
	//Output: 2NBvH4xmZYTPyDpotHWzHFy1QwY2G5C6HKP

	//Now we use the btc tesnet faucet to send some coins to the new generated address
	//This generate one output of 0.0002 BTC. Lets consume that UTXO
	input0 := multisig.UTXO{
		Hash:   "0ca18dcf29376482d6543660e0a1d734b2455f4f2309aacd8eec4024606f1300",
		Vout:   1,
		Amount: 0.0002,
	}
	//create two outputs one for a new random address and the change to our previously generated address
	destination := "mxVFsFW5N4mu1HPkxPttorvocvzeZ7KZyk"
	output0 := multisig.Output{
		Address: destination,
		Amount:  0.00015,
	}
	output1 := multisig.Output{
		Address: addr.AddressEncoded,
		Amount:  0.00001,
	}
	//the utxo and output set:
	utxos := []multisig.UTXO{input0}
	outputs := []multisig.Output{output0, output1}

	//Create our spending Transaction
	tx, err := multisig.NewSpendFromMultiSigTransaction(addr, utxos, outputs)
	if err != nil {
		panic(err)
	}

	/*
		Thanks to the multisig.NewSpendFromMultiSigTransactionWithUtxoSelection() constructor,
		 we can pass a set of utxos that point to our address
		and the transaction will be built automatically with the necessary utxos.
		The utxos with the highest output will be selected to have the smallest possible transaction size.
	*/

	//Sign with the RawPrivKey of pubkey1
	tx.Sign(privKey1, multisig.SigHashAll)

	//Sign with the wif of pubKey2
	tx.SignWithWIF(wif2String, multisig.SigHashAll)

	//Build our signature script and put it in the transaction
	tx.BuildScript()

	//Get our tx serialized in hex
	serialazedTX := tx.Serialize()

	fmt.Printf("Tx HEX: %s\n", serialazedTX)
	//We can send our raw transaction using a block explorer or a bitcoin client with 'sendrawtransaction' method

}
