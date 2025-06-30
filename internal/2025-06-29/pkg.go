package ecdsa

// https://pkg.go.dev/search?limit=100&q=ecdsa

var Pkg = []struct {
   issue string
   note  string
   url   string
}{
   {
      note: "D deprecated",
      url:  "pkg.go.dev/crypto/ecdsa",
   },
   {
      note: "secp256k1 is not compatible with secp256r1",
      url:  "pkg.go.dev/github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa",
   },
   {
      note: "github.com/btcsuite/btcd/blob/master/btcec/go.sum",
      url:  "pkg.go.dev/github.com/btcsuite/btcd/btcec/v2/ecdsa",
   },
   {
      note: "github.com/cosmos/cosmos-sdk/blob/main/go.sum",
      url:  "pkg.go.dev/github.com/cosmos/cosmos-sdk/crypto/keys/secp256r1",
   },
   {
      note: "github.com/nspcc-dev/neofs-sdk-go/blob/master/go.sum",
      url:  "pkg.go.dev/github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa",
   },
   {
      note: "github.com/renproject/id/blob/master/go.sum",
      url:  "pkg.go.dev/github.com/renproject/id",
   },
   {
      note: "github.com/hellobchain/newcryptosm/blob/main/go.sum",
      url:  "pkg.go.dev/github.com/hellobchain/newcryptosm/ecdsa",
   },
   {
      note: "secp256k1 is not compatible with secp256r1",
      url:  "pkg.go.dev/github.com/dustinxie/ecc",
   },
   {
      note: "github.com/bnb-chain/tss-lib/blob/master/go.sum",
      url:  "pkg.go.dev/github.com/bnb-chain/tss-lib/v2/ecdsa/keygen",
   },
   {
      note: "github.com/Consensys/gnark-crypto/blob/master/go.sum",
      url:  "pkg.go.dev/github.com/consensys/gnark-crypto/ecc",
   },
   {
      note: "github.com/ltcsuite/ltcd/blob/master/btcec/go.sum",
      url:  "pkg.go.dev/github.com/ltcsuite/ltcd/btcec/v2/ecdsa",
   },
   {
      note: "github.com/epicchainlabs/epicchain-sdk-go/blob/main/go.sum",
      url:  "pkg.go.dev/github.com/epicchainlabs/epicchain-sdk-go/crypto/ecdsa",
   },
   {
      note: "github.com/Consensys/gnark/blob/master/go.sum",
      url:  "pkg.go.dev/github.com/consensys/gnark/std/signature/ecdsa",
   },
   {
      note: "github.com/PaddlePaddle/PaddleDTX/blob/master/crypto/go.sum",
      url:  "pkg.go.dev/github.com/PaddlePaddle/PaddleDTX/crypto/core/ecdsa",
   },
   {
      note: "github.com/taurushq-io/multi-party-sig/blob/main/go.sum",
      url:  "pkg.go.dev/github.com/taurusgroup/multi-party-sig/pkg/ecdsa",
   },
   {
      note: "github.com/TrueCloudLab/frostfs-sdk-go/blob/master/go.sum",
      url:  "pkg.go.dev/github.com/TrueCloudLab/frostfs-sdk-go/crypto/ecdsa",
   },
   {
      note: "github.com/kubernetes/dashboard/blob/master/modules/common/certificates/go.sum",
      url:  "pkg.go.dev/github.com/kubernetes/dashboard/src/app/backend/cert/ecdsa",
   },
   {
      note: "404 github.com/MrLinnea/EEE",
      url:  "pkg.go.dev/github.com/MrLinnea/EEE/btcec/v2/ecdsa",
   },
   {
      note: "github.com/privacybydesign/gabi/blob/master/go.sum",
      url:  "pkg.go.dev/github.com/privacybydesign/gabi/signed",
   },
   {
      note: "git.frostfs.info/TrueCloudLab/frostfs-sdk-go/src/branch/master/go.sum",
      url:  "pkg.go.dev/git.frostfs.info/TrueCloudLab/frostfs-sdk-go/crypto/ecdsa",
   },
   {
      note: "github.com/libsv/go-bk/blob/master/go.sum",
      url:  "pkg.go.dev/github.com/libsv/go-bk/envelope",
   },
   {
      note: "github.com/OffchainLabs/prysm/blob/develop/go.sum",
      url:  "pkg.go.dev/github.com/prysmaticlabs/prysm/v5/crypto/ecdsa",
   },
   {
      note: "github.com/muirglacier/id/blob/master/go.sum",
      url:  "pkg.go.dev/github.com/muirglacier/id",
   },
   {
      issue: "github.com/ProtonMail/go-crypto/issues/289",
      note: "openpgp/internal/ecc: deprecated items",
      url:  "pkg.go.dev/github.com/ProtonMail/go-crypto/openpgp/ecdsa",
   },
   {
      note: "github.com/meshplus/bitxhub-kit/blob/master/go.sum",
      url: "pkg.go.dev/github.com/meshplus/bitxhub-kit/crypto/asym/ecdsa",
   },
   {
      note: "requires crypto/ecdsa",
      url: "pkg.go.dev/github.com/common-fate/httpsig/alg_ecdsa",
   },
   {
      note: "secp256r1",
      issue: "github.com/primefactor-io/ecc/issues/1",
      url: "pkg.go.dev/github.com/primefactor-io/ecc/pkg/ecdsa",
   },
   {
      note: "requires crypto/elliptic.Curve.ScalarBaseMult",
      url: "pkg.go.dev/github.com/FISCO-BCOS/crypto/ecdsa",
   },
   {
      note: "secp256k1 only",
      url: "pkg.go.dev/github.com/EXCCoin/exccd/dcrec",
   },
   {
      note: "secp256k1 only",
      url: "pkg.go.dev/github.com/Decred-Next/dcrnd/dcrec",
   },
   {
      note: "secp256k1 only",
      url: "pkg.go.dev/github.com/sebitt27/dcrd/dcrec",
   },
   {
      note: "PASS github.com/starkbank/ecdsa-go/blob/master/go.mod",
      url: "pkg.go.dev/github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa",
   },
   {
      note: "github.com/sodiumlabs/tss-lib",
      url: "pkg.go.dev/github.com/sodiumlabs/tss-lib",
   },
   {
      note: "weird",
      url: "pkg.go.dev/github.com/zeta-chain/tss-lib/ecdsa/signing",
   },
   {
      note: "weird",
      url: "pkg.go.dev/github.com/ordinox/thorchain-tss-lib/ecdsa/signing",
   },
   {
      note: "github.com/xuperchain/crypto/blob/master/go.sum",
      url: "pkg.go.dev/github.com/xuperchain/crypto",
   },
   {
      note: "gitlab.com/thorchain/tss/tss-lib/-/blob/master/go.sum",
      url: "pkg.go.dev/gitlab.com/thorchain/tss/tss-lib/ecdsa/signing",
   },
   {
      note: "fucking stupid",
      url: "pkg.go.dev/github.com/tink-crypto/tink-go/v2/signature/ecdsa",
   },
   {
      note: "secp256k1 only",
      url: "pkg.go.dev/github.com/multicash/mcxd/mcxec",
   },
   {
      note: "secp256k1 only",
      url: "pkg.go.dev/github.com/Decred-Next/dcrnd/dcrec",
   },
   {
      note: "github.com/AVecsi/pq-gabi/blob/master/go.sum",
      url: "pkg.go.dev/github.com/AVecsi/pq-gabi/signed",
   },
   {
      note: "github.com/libp2p/go-libp2p/blob/master/go.sum",
      url: "pkg.go.dev/github.com/libp2p/go-libp2p/core/crypto",
   },
   {
      note: "uses crypto/ecdsa",
      url: "pkg.go.dev/github.com/libs4go/crypto/ecdsa",
   },
   {
      note: "github.com/Layr-Labs/eigensdk-go/blob/dev/go.sum",
      url: "pkg.go.dev/github.com/Layr-Labs/eigensdk-go/crypto/ecdsa",
   },
   {
      note: "fucking stupid",
      url: "pkg.go.dev/github.com/sonr-io/multi-party-sig/pkg/ecdsa",
   },
   {
      note: "git.chainmaker.org.cn/chainmaker/common/-/blob/master/go.sum",
      url: "pkg.go.dev/chainmaker.org/chainmaker/common/v3/crypto/asym/ecdsa",
   },
   {
      note: "ScalarBaseMult is deprecated",
      issue: "github.com/cloudflare/pat-go/issues/61",
      url: "pkg.go.dev/github.com/cloudflare/pat-go/ecdsa",
   },
   {
      note: "crypto/ecdsa need way to generate PrivateKey from bytes",
      issue: "github.com/runZeroInc/excrypto/issues/37",
      url: "pkg.go.dev/github.com/runZeroInc/excrypto/crypto/ecdsa",
   },
   {
      note: "ECDSA key from bytes",
      issue: "github.com/svicknesh/key/issues/1",
      url: "pkg.go.dev/github.com/svicknesh/key/v2",
   },
   {
      note: "ecdsa: need way to generate PrivateKey from bytes",
      issue: "github.com/A1andNS/newCrypto/issues/1",
      url: "https://pkg.go.dev/github.com/A1andNS/newCrypto/ecdsa",
   },
   {
      note: "weird",
      url: "pkg.go.dev/github.com/okx/threshold-lib/tss/ecdsa/sign",
   },
   {
      note: "github.com/flokiorg/go-flokicoin/blob/main/go.sum",
      url: "pkg.go.dev/github.com/flokiorg/go-flokicoin/crypto/ecdsa",
   },
   {
      note: "no sign",
      url: "pkg.go.dev/github.com/0xPellNetwork/pelldvs-libs/crypto/ecdsa",
   },
   {
      note: "github.com/opzlabs/cosmos-sdk-terra3/blob/main/go.sum",
      url: "pkg.go.dev/github.com/opzlabs/cosmos-sdk-v0.46.13-terra.3/crypto/keys/secp256r1",
   },
   {
      note: "no sign",
      url: "pkg.go.dev/gitlab.com/alephledger/threshold-ecdsa/pkg",
   },
   {
      note: "old",
      url: "pkg.go.dev/github.com/GM-Publicchain/gm/plugin/crypto/ecdsa",
   },
   {
      note: "archived",
      url: "pkg.go.dev/github.com/keep-network/keep-ecdsa/pkg/ecdsa",
   },
   {
      note: "go.mod",
      issue: "github.com/PutinCoinPUT/ppcd/issues/1",
      url: "pkg.go.dev/github.com/PutinCoinPUT/ppcd/btcec/ecdsa",
   },
   {
      note: "EccFrog512CK2 elliptic curve",
      url: "github.com/shovon/go-eccfrog512ck2/ecc/ecdsa",
   },
   {
      note: "publish",
      url: "github.com/shovon/elliptic-curve-pointless/issues/1",
   },
   {
      note: "ECDSA import key raw",
      issue: "github.com/armortal/webcrypto-go/issues/39",
      url: "pkg.go.dev/github.com/armortal/webcrypto-go/algorithms/ecdsa",
   },
   /*
   ecdsa (github.com/vocdoni/gnark-crypto-bn254/ecc/bn254/ecdsa)
   Package ecdsa provides ECDSA signature scheme on the bn254 curve.
   Imported by 0
   | v0.10.1 published on Apr 2, 2023 | Apache-2.0

   ecdsa (github.com/BeratOz01/gnark/std/signature/ecdsa)
   Package ecdsa implements ECDSA signature verification over any elliptic curve.
   Imported by 0
   | v0.0.0-...-ae8e47d published on Mar 25, 2023 | Apache-2.0

   ecdsa (github.com/Overclock-Validator/gnark-crypto/ecc/bls12-377/ecdsa)
   Package ecdsa provides ECDSA signature scheme on the bls12-377 curve.
   Imported by 0
   | v0.0.0-...-68aa4a9 published on Mar 9, 2025 | Apache-2.0
   Other packages in module github.com/Overclock-Validator/gnark-crypto:
   ecc/bls12-381/ecdsa
   ecc/bls24-315/ecdsa
   ecc/bls24-317/ecdsa
   ecc/bn254/ecdsa
   ecc/bw6-633/ecdsa
   +4 more

   ecdsa (github.com/RonanThoraval/gnark/std/signature/ecdsa)
   Package ecdsa implements ECDSA signature verification over any elliptic curve.
   Imported by 0
   | v0.0.0-...-4c0a751 published on Oct 7, 2024 | Apache-2.0

   ecdsa (github.com/denpeshkov/httpsign/ecdsa)
   Package ecdsa provides utilities for signing and verifying messages using ECDSA.
   Imported by 0
   | v0.2.0 published on Nov 15, 2024 | MIT

   ecdsa (github.com/common-library/go/security/crypto/ecdsa)
   Package ecdsa provides ecdsa crypto related implementations.
   Imported by 0
   | v1.2.2 published on May 5, 2025 | Apache-2.0

   ecdsa (github.com/pierreleocadie/SecuraChain/pkg/ecdsa)
   Package ecdsa provides utilities for generating and managing ECDSA key pairs.
   Imported by 0
   | v1.0.0-release published on May 19, 2024 | MIT

   ecdsa (github.com/ldclabs/cose/key/ecdsa)
   Package ecdsa implements signature algorithm ECDSA for COSE as defined in RFC9053.
   Imported by 0
   | v1.3.2 published on Sep 29, 2024 | MIT
   */
}
