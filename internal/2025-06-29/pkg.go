package ecdsa

// https://pkg.go.dev/search?limit=100&q=ecdsa

var pkg = []struct {
   go_sum int
   issue  string
   spec   string
}{
   {
      go_sum: 2,
      spec: "github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa",
   },
   {
      go_sum: 10,
      spec: "github.com/arnaucube/cryptofun/ecdsa",
   },
/////////////////////////////////////////////////////////////////////////////////
   {
      issue: "no sign",
      spec: "github.com/aureleoules/ecdsa",
   },
   {
      issue: `github.com/deatil/go-cryptobin/issues/38
      deprecated methods`,
      spec: "github.com/deatil/go-cryptobin/cryptobin/ecdsa",
   },
   {
      issue: "go mod tidy fail",
      spec: "github.com/bnb-chain/tss-lib/v2/ecdsa/signing",
   },
   {
      issue: "secp256k1 only",
      spec:   "github.com/btcsuite/btcd/btcec/v2/ecdsa",
   },
   {
      issue: `github.com/common-library/go/issues/158
      elliptic curve math`,
      spec: "github.com/common-library/go/security/crypto/ecdsa",
   },
   {
      go_sum: 12,
      spec: "github.com/libsv/go-bk/envelope",
   },
   {
      go_sum: 16,
      spec: "github.com/AVecsi/pq-gabi/signed",
   },
   {
      go_sum: 16,
      spec: "github.com/privacybydesign/gabi/signed",
   },
   {
      go_sum: 18,
      spec: "github.com/taurusgroup/multi-party-sig/pkg/ecdsa",
   },
   {
      go_sum: 18,
      spec:   "github.com/ldclabs/cose/key/ecdsa",
   },
   {
      go_sum: 23,
      spec: "github.com/PaddlePaddle/PaddleDTX/crypto/core/ecdsa",
   },
   {
      go_sum: 49,
      spec: "git.frostfs.info/TrueCloudLab/frostfs-sdk-go/crypto/ecdsa",
   },
   {
      go_sum: 54,
      spec: "github.com/consensys/gnark/std/signature/ecdsa",
   },
   {
      go_sum: 56,
      spec:   "github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa",
   },
   {
      go_sum: 78,
      spec: "github.com/prysmaticlabs/prysm/v5/crypto/ecdsa",
   },
   {
      go_sum: 85,
      spec: "github.com/renproject/id",
   },
   {
      go_sum: 96,
      spec: "github.com/kubernetes/dashboard/src/app/backend/cert/ecdsa",
   },
   {
      go_sum: 133,
      spec: "github.com/hellobchain/newcryptosm/ecdsa",
   },
   {
      go_sum: 161,
      spec: "github.com/TrueCloudLab/frostfs-sdk-go/crypto/ecdsa",
   },
   {
      go_sum: 230,
      spec:   "github.com/cosmos/cosmos-sdk/crypto/keys/secp256r1",
   },
   {
      issue: `pkg.go.dev/crypto/ecdsa@go1.25rc1#PublicKey.X
      pkg.go.dev/crypto/ecdsa@go1.25rc1#PublicKey.Y`,
      spec:  "crypto/ecdsa",
   },
   {
      issue: "requires crypto/ecdsa",
      spec: "github.com/xuperchain/crypto/core/sign",
   },
   {
      issue: "requires crypto/ecdsa",
      spec: "github.com/xuperchain/crypto/gm/sign",
   },
   {
      issue: "secp256k1 only",
      spec:  "github.com/decred/dcrd/dcrec",
   },
   {
      issue: "secp256k1 is not compatible with secp256r1",
      spec: "github.com/dustinxie/ecc",
   },
   {
      issue: "secp256k1 only",
      spec: "github.com/consensys/gnark-crypto/ecc",
   },
   {
      issue: "go mod tidy fail",
      spec: "github.com/epicchainlabs/epicchain-sdk-go/crypto/ecdsa",
   },
   {
      issue: "404 github.com/MrLinnea/EEE",
      spec: "github.com/MrLinnea/EEE/btcec/v2/ecdsa",
   },
   {
      issue: "go mod tidy fail",
      spec: "github.com/muirglacier/id",
   },
   {
      go_sum: 668,
      spec: "github.com/meshplus/bitxhub-kit/crypto/asym/ecdsa",
   },
   {
      issue: "secp256k1 only",
      spec: "github.com/EXCCoin/exccd/dcrec",
   },
   {
      issue: "secp256k1 only",
      spec: "github.com/Decred-Next/dcrnd/dcrec",
   },
   {
      issue: "secp256k1 only",
      spec: "github.com/sebitt27/dcrd/dcrec",
   },
   {
      issue: "go mod tidy fail",
      spec: "gitlab.com/thorchain/tss/tss-lib/ecdsa/signing",
   },
   {
      issue: "weird",
      spec: "github.com/ordinox/thorchain-tss-lib/ecdsa/signing",
   },
   {
      issue: "404 github.com/sodiumlabs/tss-lib",
      spec: "github.com/sodiumlabs/tss-lib",
   },
   {
      issue: "weird",
      spec: "github.com/zeta-chain/tss-lib/ecdsa/signing",
   },
   {
      issue: "secp256k1 only",
      spec: "github.com/Decred-Next/dcrnd/dcrec",
   },
   {
      issue: `github.com/primefactor-io/ecc/issues/1
      secp256r1`,
      spec:  "github.com/primefactor-io/ecc/pkg/ecdsa",
   },
   {
      issue: "requires crypto/ecdsa",
      spec: "github.com/common-fate/httpsig/alg_ecdsa",
   },
   {
      issue: "requires crypto/elliptic.Curve.ScalarBaseMult",
      spec: "github.com/FISCO-BCOS/crypto/ecdsa",
   },
   {
      go_sum: 78,
      spec: "github.com/OffchainLabs/prysm/v6/crypto/ecdsa",
   },
   {
      issue: "uses crypto/ecdsa",
      spec: "github.com/libs4go/crypto/ecdsa",
   },
   {
      go_sum: 87,
      spec: "github.com/Layr-Labs/eigensdk-go/crypto/ecdsa",
   },
   {
      issue: "cursed",
      spec: "github.com/keep-network/keep-core/pkg/chain/ethereum/ecdsa",
   },
   {
      issue: `github.com/cloudflare/pat-go/issues/61
      ScalarBaseMult is deprecated`,
      spec:  "github.com/cloudflare/pat-go/ecdsa",
   },
   {
      issue: "go mod tidy fail",
      spec: "chainmaker.org/chainmaker/common/v3/crypto/asym/ecdsa",
   },
   {
      issue: `github.com/runZeroInc/excrypto/issues/37
      crypto/ecdsa need way to generate PrivateKey from bytes`,
      spec:  "github.com/runZeroInc/excrypto/crypto/ecdsa",
   },
   {
      issue: `github.com/svicknesh/key/issues/1
      ECDSA key from bytes`,
      spec:  "github.com/svicknesh/key/v2",
   },
   {
      issue: "go mod tidy fail",
      spec: "github.com/sonrhq/sonr/crypto/signatures/ecdsa",
   },
   {
      issue: "no sign",
      spec: "github.com/0xPellNetwork/pelldvs-libs/crypto/ecdsa",
   },
   {
      issue: "no sign",
      spec: "gitlab.com/alephledger/threshold-ecdsa/pkg",
   },
   {
      issue: "old",
      spec: "github.com/GM-Publicchain/gm/plugin/crypto/ecdsa",
   },
   {
      issue: "archived",
      spec: "github.com/keep-network/keep-ecdsa/pkg/ecdsa",
   },
   {
      go_sum: 69,
      spec: "github.com/pierreleocadie/SecuraChain/pkg/ecdsa",
   },
   {
      issue: "secp256k1 only",
      spec: "github.com/multicash/mcxd/mcxec",
   },
   {
      issue: "secp256k1 only",
      spec: "github.com/wertikalk/gnark-crypto/ecc",
   },
   {
      issue: "go mod tidy fail",
      spec: "github.com/RonanThoraval/gnark/std/signature/ecdsa",
   },
   {
      issue: "go mod tidy fail",
      spec: "github.com/airchains-network/gnark/std/signature/ecdsa",
   },
   {
      issue: `github.com/A1andNS/newCrypto/issues/1
      ecdsa: need way to generate PrivateKey from bytes`,
      spec:  "https://github.com/A1andNS/newCrypto/ecdsa",
   },
   {
      issue: `github.com/PutinCoinPUT/ppcd/issues/1
      go.mod`,
      spec:  "github.com/PutinCoinPUT/ppcd/btcec/ecdsa",
   },
   {
      issue: "go mod tidy fail",
      spec: "github.com/aakash4dev/gnark2/std/signature/ecdsa",
   },
   {
      issue: "secp256r1 missing",
      spec: "github.com/vocdoni/gnark-crypto-bn254/ecc",
   },
   {
      go_sum: 54,
      spec: "github.com/libp2p/go-libp2p/core/crypto",
   },
   {
      issue: "EccFrog512CK2 elliptic curve",
      spec: "github.com/shovon/go-eccfrog512ck2/ecc/ecdsa",
   },
   {
      issue: "publish",
      spec: "github.com/shovon/elliptic-curve-pointless/issues/1",
   },
   {
      issue: "go mod tidy fail",
      spec: "github.com/BeratOz01/gnark/std/signature/ecdsa",
   },
   {
      issue: "uses crypto/ecdsa",
      spec: "github.com/denpeshkov/httpsign/ecdsa",
   },
   {
      issue: `github.com/armortal/webcrypto-go/issues/39
      ECDSA import key raw`,
      spec:  "github.com/armortal/webcrypto-go/algorithms/ecdsa",
   },
   {
      issue: "secp256k1 only",
      spec: "github.com/flokiorg/go-flokicoin/crypto/ecdsa",
   },
   {
      issue: "secp256k1 only",
      spec: "github.com/ltcsuite/ltcd/btcec/v2/ecdsa",
   },
   {
      issue: "secp256k1 only",
      spec: "github.com/tinyverse-web3/btcd/btcec/v2/ecdsa",
   },
}
