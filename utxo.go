package btcmultisig

type UTXO struct {
	Hash   string
	Vout   int
	Amount float64
}

type Output struct {
	Address string
	Amount  float64
}
