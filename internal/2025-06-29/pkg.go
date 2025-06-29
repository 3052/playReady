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
   /*
   key (github.com/svicknesh/key/v2)
   Imported by 2
   | v2.1.3 published on 4 days ago | MIT
   Other major versions: v1

   ecdsa (github.com/A1andNS/newCrypto/ecdsa)
   Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-3.
   Imported by 2
   | v0.0.0-...-3d4b386 published on Jan 10, 2025 | BSD-3-Clause

   tokenauth (github.com/gobuffalo/mw-tokenauth)
   Package tokenauth provides jwt token authorisation middleware supports HMAC, RSA, ECDSA, RSAPSS EdDSA algorithms uses github.com/golang-jwt/jwt/v4 for jwt implementation
   Imported by 2
   | v1.0.2 published on Feb 15, 2023 | MIT

   keygen (github.com/okx/threshold-lib/tss/ecdsa/keygen)
   Imported by 2
   | v1.0.1 published on Aug 28, 2023 | Apache-2.0
   Other packages in module github.com/okx/threshold-lib:
   tss/ecdsa/sign

   ecdsa (github.com/sonrhq/sonr/crypto/signatures/ecdsa)
   Imported by 2
   | v0.16.1 published on Mar 10, 2024 | GPL-3.0

   ecdsa (github.com/flokiorg/go-flokicoin/crypto/ecdsa)
   Imported by 2
   | v0.25.6-dev published on May 2, 2025 | ISC

   ecdsa (github.com/0xPellNetwork/pelldvs-libs/crypto/ecdsa)
   Imported by 2
   | v0.2.2 published on Jun 13, 2025 | Apache-2.0

   secp256r1 (github.com/opzlabs/cosmos-sdk-v0.46.13-terra.3/crypto/keys/secp256r1)
   Package secp256r1 implements Cosmos-SDK compatible ECDSA public and private key.
   Imported by 2
   | v0.1.3 published on Sep 18, 2023 | Apache-2.0

   curve (gitlab.com/alephledger/threshold-ecdsa/pkg/curve)
   Imported by 4
   | v0.0.0-...-abd57cf published on Mar 5, 2021 | Apache-2.0
   Other packages in module gitlab.com/alephledger/threshold-ecdsa:
   pkg/crypto/commitment
   pkg/sync
   pkg/crypto
   pkg/arith
   pkg/crypto/zkpok
   +1 more


   ecdsa (github.com/GM-Publicchain/gm/plugin/crypto/ecdsa)
   Imported by 4
   | v0.0.0-...-0abe6a2 published on Sep 19, 2019 | BSD-3-Clause

   keep-ecdsa (github.com/keep-network/keep-ecdsa)
   command
   Imported by 0
   | v1.8.2 published on Sep 14, 2022 | MIT
   Other packages in module github.com/keep-network/keep-ecdsa:
   pkg/ecdsa
   pkg/chain
   pkg/client
   pkg/ecdsa/tss

   ecdsa (gopkg.in/zhevron/jwt.v1/ecdsa)
   Package ecdsa provides ECDSA signing methods for JWT.
   Imported by 1
   | v1.0.0-...-79c4aa1 published on Apr 15, 2015 | MIT

   ecdsa (github.com/PutinCoinPUT/ppcd/btcec/ecdsa)
   Imported by 3
   | v0.0.0-...-3ecc070 published on Jan 31, 2024 | MIT

   jwkgen (github.com/glamorouscub/jwkgen)
   command
   Imported by 0
   | v0.0.0-...-d06e9d8 published on Feb 27, 2025 | MIT

   ecdsa (github.com/shovon/go-eccfrog512ck2/ecc/ecdsa)
   Package ecdsa provides helpers for signing and verifying signatures using the ECDSA cryptographic scheme, operated on the EccFrog512ck2 family of curves.
   Imported by 0
   | v0.1.0 published on Jun 18, 2025 | MIT

   jwkgen (github.com/necessaryeros/jwkgen)
   command
   Imported by 0
   | v0.0.0-...-9cb2e34 published on May 6, 2025 | MIT

   ecdsa (github.com/aakash4dev/gnark2/std/signature/ecdsa)
   Package ecdsa implements ECDSA signature verification over any elliptic curve.
   Imported by 0
   | v0.0.0-...-70ee9f5 published on Dec 19, 2023 | Apache-2.0

   jwkgen (github.com/rakutentech/jwkgen)
   command
   Imported by 0
   | v1.4.8 published on Jul 15, 2024 | MIT

   ecdsa (github.com/armortal/webcrypto-go/algorithms/ecdsa)
   Package ecdsa implements ECDSA operations as described in the specifications at §23 (https://www.w3.org/TR/WebCryptoAPI/#ecdsa).
   Imported by 0
   | v0.1.0 published on Jan 22, 2025 | Apache-2.0
   Other packages in module github.com/armortal/webcrypto-go:
   examples/ecdsa

   ecdsa (github.com/vocdoni/gnark-crypto-bn254/ecc/bn254/ecdsa)
   Package ecdsa provides ECDSA signature scheme on the bn254 curve.
   Imported by 0
   | v0.10.1 published on Apr 2, 2023 | Apache-2.0

   ecdsa (github.com/BeratOz01/gnark/std/signature/ecdsa)
   Package ecdsa implements ECDSA signature verification over any elliptic curve.
   Imported by 0
   | v0.0.0-...-ae8e47d published on Mar 25, 2023 | Apache-2.0

   jwkgen (github.com/frostyrest/jwkgen)
   command
   Imported by 0
   | v0.0.0-...-36f70b0 published on May 18, 2025 | MIT

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
