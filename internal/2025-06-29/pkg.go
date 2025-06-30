package ecdsa

// https://pkg.go.dev/search?limit=100&q=ecdsa

var Pkg = []struct {
   go_sum int
   issue  string
   spec   string
}{
   {
      go_sum: 2,
      spec: "github.com/xuperchain/crypto/core/sign",
   },
   {
      go_sum: 6,
      spec: "github.com/xuperchain/crypto/gm/sign",
   },
   {
      go_sum: 2,
      spec: "github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa",
   },
   {
      go_sum: 10,
      spec: "github.com/ltcsuite/ltcd/btcec/v2/ecdsa",
   },
   {
      go_sum: 10,
      spec:   "github.com/btcsuite/btcd/btcec/v2/ecdsa",
   },
   {
      go_sum: 12,
      spec: "github.com/libsv/go-bk/envelope",
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
      issue: "D deprecated",
      spec:  "crypto/ecdsa",
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
      issue: "go mod tidy fail",
      spec: "github.com/bnb-chain/tss-lib/v2/ecdsa/signing",
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
   /*
   keygen (github.com/zeta-chain/tss-lib/ecdsa/keygen)
   Imported by 7
   | v0.1.7 published on Oct 27, 2023 | MIT
   Other packages in module github.com/zeta-chain/tss-lib:
   ecdsa/signing

   ecdsa (github.com/Decred-Next/dcrnd/dcrec/secp256k1/version3/v8/ecdsa)
   Package ecdsa provides secp256k1-optimized ECDSA signing and verification.
   Imported by 2
   | v8.0.12 published on Jun 27, 2022 | ISC

   ecdsa (github.com/multicash/mcxd/mcxec/secp256k1/v4/ecdsa)
   Package ecdsa provides secp256k1-optimized ECDSA signing and verification.
   Imported by 2
   | v4.0.0-...-14ed8ac published on Feb 25, 2021 | ISC

   ecdsa_go_proto (github.com/google/tink/go/proto/ecdsa_go_proto)
   Imported by 5
   | v1.7.0 published on Aug 10, 2022 | Apache-2.0

   signed (github.com/AVecsi/pq-gabi/signed)
   Package signed contains (1) convenience functions for ECDSA private and public key handling, and for signing and verifying byte slices with ECDSA; (2) functions for marshaling structs to signed bytes, and verifying and unmarshaling signed bytes back to structs.
   Imported by 2
   | v0.0.0-...-7ee7d8d published on Jun 23, 2025 | BSD-3-Clause

   certsetup (github.com/wostzone/hubserve-go/pkg/certsetup)
   Package certsetup with server side creation of self signed certificate chain using ECDSA Credits: https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251 keys
   Imported by 4
   | v0.0.0-...-4ab42d6 published on Nov 7, 2021 | MIT

   ecdsa (github.com/OffchainLabs/prysm/v6/crypto/ecdsa)
   Imported by 4
   | v6.0.4 published on Jun 2, 2025 | GPL-3.0

   set_ecdsa (github.com/theupdateframework/go-tuf/pkg/deprecated/set_ecdsa)
   Imported by 4
   | v0.7.0 published on Nov 28, 2023 | BSD-3-Clause

   ecdsa (github.com/libs4go/crypto/ecdsa)
   Imported by 4
   | v0.0.1 published on Sep 9, 2021 | MIT

   ecdsa (github.com/Layr-Labs/eigensdk-go/crypto/ecdsa)
   Imported by 39
   | v0.3.0 published on Mar 19, 2025 | UNKNOWN

   ecdsa (github.com/amitkgupta/go-smarthealthcards/v2/ecdsa)
   Package ecdsa loads an ECDSA P-256 private key (*crypto/ecdsa.PrivateKey) from string representations of its key parameters.
   Imported by 1
   | v2.0.1 published on Dec 5, 2021 | MIT
   Other major versions: v1
   Other packages in module github.com/amitkgupta/go-smarthealthcards/v2:
   jws

   ecdsa (github.com/hdfchain/hdfd/dcrec/secp256k1/v3/ecdsa)
   Package ecdsa provides secp256k1-optimized ECDSA signing and verification.
   Imported by 1
   | v3.0.0-...-3464dac published on Oct 8, 2020 | ISC

   ecdsa (github.com/sonr-io/multi-party-sig/pkg/ecdsa)
   Imported by 3
   | v0.7.0 published on Jun 13, 2022 | Apache-2.0

   ecdsa (chainmaker.org/chainmaker/common/v2/crypto/asym/ecdsa)
   nolint
   Imported by 3
   | v2.4.0 published on May 28, 2025 | Apache-2.0

   abi (github.com/keep-network/keep-core/pkg/chain/ethereum/ecdsa/gen/abi)
   Imported by 3
   | v1.21.0 published on Feb 1, 2024 | MIT
   Other packages in module github.com/keep-network/keep-core:
   pkg/chain/ethereum/ecdsa/gen/contract
   pkg/chain/ethereum/ecdsa/gen
   pkg/chain/ethereum/ecdsa/gen/cmd

   ecdsa (github.com/tinyverse-web3/btcd/btcec/v2/ecdsa)
   Imported by 3
   | v2.3.4 published on Aug 21, 2024 | ISC

   secp256k1 (github.com/ltcsuite/secp256k1)
   Imported by 3
   | v0.1.1 published on May 5, 2025 | MIT

   secp256k1 (github.com/ltcmweb/secp256k1)
   Imported by 3
   | v0.1.1 published on Sep 1, 2024 | MIT

   ecdsa (github.com/cloudflare/pat-go/ecdsa)
   Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-3.
   Imported by 1
   | v0.0.0-...-555c9a4 published on Jun 11, 2025 | BSD-3-Clause

   ecdsa (github.com/runZeroInc/excrypto/crypto/ecdsa)
   Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-4 and SEC 1, Version 2.0.
   Imported by 1
   | v0.0.0-...-7e62a70 published on 5 hours ago | Apache-2.0, BSD-3-Clause, GooglePatentsFile, MIT

   ecdsa (github.com/relab/hotstuff/crypto/ecdsa)
   Package ecdsa provides a crypto implementation for HotStuff using Go's 'crypto/ecdsa' package.
   Imported by 1
   | v0.4.0 published on Dec 6, 2021 | MIT

   key (github.com/svicknesh/key/v2)
   Imported by 2
   | v2.1.3 published on 5 days ago | MIT
   Other major versions: v1

   ecdsa (github.com/flokiorg/go-flokicoin/crypto/ecdsa)
   Imported by 2
   | v0.25.6-dev published on May 2, 2025 | ISC

   ecdsa (github.com/sonrhq/sonr/crypto/signatures/ecdsa)
   Imported by 2
   | v0.16.1 published on Mar 10, 2024 | GPL-3.0

   ecdsa (github.com/0xPellNetwork/pelldvs-libs/crypto/ecdsa)
   Imported by 2
   | v0.2.2 published on Jun 13, 2025 | Apache-2.0

   keygen (github.com/okx/threshold-lib/tss/ecdsa/keygen)
   Imported by 2
   | v1.0.1 published on Aug 28, 2023 | Apache-2.0
   Other packages in module github.com/okx/threshold-lib:
   tss/ecdsa/sign

   ecdsa (github.com/A1andNS/newCrypto/ecdsa)
   Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-3.
   Imported by 2
   | v0.0.0-...-3d4b386 published on Jan 10, 2025 | BSD-3-Clause

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

   sign (github.com/ORBAT/Peerdoc/pkg/crypto/sign)
   package sign provides a standardized interface for cryptographic signatures and a default implementation with ECDSA with the secp256k1 curve.
   Imported by 4
   | v0.0.0-...-2f646e5 published on Mar 11, 2019 | MIT

   keep-ecdsa (github.com/keep-network/keep-ecdsa)
   command
   Imported by 0
   | v1.8.2 published on Sep 14, 2022 | MIT
   Other packages in module github.com/keep-network/keep-ecdsa:
   pkg/ecdsa
   pkg/chain
   pkg/client
   pkg/ecdsa/tss

   ecdsa (github.com/PutinCoinPUT/ppcd/btcec/ecdsa)
   Imported by 3
   | v0.0.0-...-3ecc070 published on Jan 31, 2024 | MIT

   ecdsa (ec.mleku.dev/v2/ecdsa)
   Package ecdsa provides secp256k1-optimized ECDSA signing and verification.
   Imported by 0
   | v2.3.5 published on Jul 27, 2024 | ISC

   ecdsa (github.com/aakash4dev/gnark2/std/signature/ecdsa)
   Package ecdsa implements ECDSA signature verification over any elliptic curve.
   Imported by 0
   | v0.0.0-...-70ee9f5 published on Dec 19, 2023 | Apache-2.0

   ecdsa (github.com/mleku/btcec/ecdsa)
   Package ecdsa provides secp256k1-optimized ECDSA signing and verification.
   Imported by 0
   | v1.0.1 published on Jul 11, 2024 | ISC

   ecdsa (mleku.online/git/ec/ecdsa)
   Package ecdsa provides secp256k1-optimized ECDSA signing and verification.
   Imported by 0
   | v1.0.7 published on Feb 16, 2024 | ISC

   ecdsa (github.com/pierreleocadie/SecuraChain/pkg/ecdsa)
   Package ecdsa provides utilities for generating and managing ECDSA key pairs.
   Imported by 0
   | v1.0.0-release published on May 19, 2024 | MIT

   jwkgen (github.com/necessaryeros/jwkgen)
   command
   Imported by 0
   | v0.0.0-...-9cb2e34 published on May 6, 2025 | MIT

   ecdsa (github.com/wertikalk/gnark-crypto/ecc/bls12-377/ecdsa)
   Package ecdsa provides ECDSA signature scheme on the bls12-377 curve.
   Imported by 0
   | v0.0.0-...-6c19a75 published on Aug 4, 2024 | Apache-2.0
   Other packages in module github.com/wertikalk/gnark-crypto:
   ecc/bls12-378/ecdsa
   ecc/bls12-381/ecdsa
   ecc/bls24-315/ecdsa
   ecc/bls24-317/ecdsa
   ecc/bn254/ecdsa
   +5 more

   ecdsa (github.com/danivilardell/gnark/v2/std/signature/ecdsa)
   Package ecdsa implements ECDSA signature verification over any elliptic curve.
   Imported by 0
   | v2.0.0 published on Jul 18, 2024 | Apache-2.0
   Other major versions: v1

   jwkgen (github.com/frostyrest/jwkgen)
   command
   Imported by 0
   | v0.0.0-...-36f70b0 published on May 18, 2025 | MIT

   ecdsa (mleku.net/ec/ecdsa)
   Package ecdsa provides secp256k1-optimized ECDSA signing and verification.
   Imported by 0
   | v1.0.11 published on Jun 2, 2024 | ISC

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

   ecdsa (github.com/common-library/go/security/crypto/ecdsa)
   Package ecdsa provides ecdsa crypto related implementations.
   Imported by 0
   | v1.2.2 published on May 5, 2025 | Apache-2.0

   ecdsa (github.com/RonanThoraval/gnark/std/signature/ecdsa)
   Package ecdsa implements ECDSA signature verification over any elliptic curve.
   Imported by 0
   | v0.0.0-...-4c0a751 published on Oct 7, 2024 | Apache-2.0

   ecdsa (github.com/airchains-network/gnark/std/signature/ecdsa)
   Package ecdsa implements ECDSA signature verification over any elliptic curve.
   Imported by 0
   | v1.0.1 published on Dec 19, 2023 | Apache-2.0

   ecdsa (relay.mleku.dev/ec/ecdsa)
   Package ecdsa provides secp256k1-optimized ECDSA signing and verification.
   Imported by 0
   | v0.0.0-...-d6038a4 published on Apr 21, 2025 | CC0-1.0, ISC

   ecdsa (github.com/Hubmakerlabs/replicatr/pkg/ec/ecdsa)
   Package ecdsa provides secp256k1-optimized ECDSA signing and verification.
   Imported by 0
   | v1.2.17 published on Jul 9, 2024 | GPL-2.0, ISC

   ecdsa (realy.lol/ec/ecdsa)
   Package ecdsa provides secp256k1-optimized ECDSA signing and verification.
   Imported by 0
   | v1.19.0 published on May 24, 2025 | ISC, Unlicense

   ecdsa (github.com/armortal/webcrypto-go/algorithms/ecdsa)
   Package ecdsa implements ECDSA operations as described in the specifications at §23 (https://www.w3.org/TR/WebCryptoAPI/#ecdsa).
   Imported by 0
   | v0.1.0 published on Jan 22, 2025 | Apache-2.0
   Other packages in module github.com/armortal/webcrypto-go:
   examples/ecdsa

   ecdsa (mleku.net/g/m/pkg/ec/ecdsa)
   Package ecdsa provides secp256k1-optimized ECDSA signing and verification.
   Imported by 0
   | v0.0.6 published on Jun 10, 2024 | CC0-1.0, ISC

   ecdsa (github.com/vocdoni/gnark-crypto-bn254/ecc/bn254/ecdsa)
   Package ecdsa provides ECDSA signature scheme on the bn254 curve.
   Imported by 0
   | v0.10.1 published on Apr 2, 2023 | Apache-2.0

   jwkgen (github.com/glamorouscub/jwkgen)
   command
   Imported by 0
   | v0.0.0-...-d06e9d8 published on Feb 27, 2025 | MIT
   */
}

var Pkg_old = []struct {
   issue  string
   spec  string
}{
   {
      issue: "weird",
      spec: "github.com/zeta-chain/tss-lib/ecdsa/signing",
   },
   {
      issue: "fucking stupid",
      spec: "github.com/tink-crypto/tink-go/v2/signature/ecdsa",
   },
   {
      issue: "secp256k1 only",
      spec: "github.com/multicash/mcxd/mcxec",
   },
   {
      issue: "secp256k1 only",
      spec: "github.com/Decred-Next/dcrnd/dcrec",
   },
   {
      issue: "github.com/AVecsi/pq-gabi/blob/master/go.sum",
      spec: "github.com/AVecsi/pq-gabi/signed",
   },
   {
      issue: "github.com/libp2p/go-libp2p/blob/master/go.sum",
      spec: "github.com/libp2p/go-libp2p/core/crypto",
   },
   {
      issue: "uses crypto/ecdsa",
      spec: "github.com/libs4go/crypto/ecdsa",
   },
   {
      issue: "github.com/Layr-Labs/eigensdk-go/blob/dev/go.sum",
      spec: "github.com/Layr-Labs/eigensdk-go/crypto/ecdsa",
   },
   {
      issue: "fucking stupid",
      spec: "github.com/sonr-io/multi-party-sig/pkg/ecdsa",
   },
   {
      issue: "git.chainmaker.org.cn/chainmaker/common/-/blob/master/go.sum",
      spec: "chainmaker.org/chainmaker/common/v3/crypto/asym/ecdsa",
   },
   {
      issue: `github.com/cloudflare/pat-go/issues/61
      ScalarBaseMult is deprecated`,
      spec:  "github.com/cloudflare/pat-go/ecdsa",
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
      issue: `github.com/A1andNS/newCrypto/issues/1
      ecdsa: need way to generate PrivateKey from bytes`,
      spec:  "https://github.com/A1andNS/newCrypto/ecdsa",
   },
   {
      issue: "weird",
      spec: "github.com/okx/threshold-lib/tss/ecdsa/sign",
   },
   {
      issue: "github.com/flokiorg/go-flokicoin/blob/main/go.sum",
      spec: "github.com/flokiorg/go-flokicoin/crypto/ecdsa",
   },
   {
      issue: "no sign",
      spec: "github.com/0xPellNetwork/pelldvs-libs/crypto/ecdsa",
   },
   {
      issue: "github.com/opzlabs/cosmos-sdk-terra3/blob/main/go.sum",
      spec: "github.com/opzlabs/cosmos-sdk-v0.46.13-terra.3/crypto/keys/secp256r1",
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
      issue: `github.com/PutinCoinPUT/ppcd/issues/1
      go.mod`,
      spec:  "github.com/PutinCoinPUT/ppcd/btcec/ecdsa",
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
      issue: `github.com/armortal/webcrypto-go/issues/39
      ECDSA import key raw`,
      spec:  "github.com/armortal/webcrypto-go/algorithms/ecdsa",
   },
   {
      issue: "github.com/BeratOz01/gnark/blob/master/go.sum",
      spec: "github.com/BeratOz01/gnark/std/signature/ecdsa",
   },
   {
      issue: "fork",
      spec: "github.com/Overclock-Validator/gnark-crypto/ecc",
   },
   {
      issue: "uses crypto/ecdsa",
      spec: "github.com/denpeshkov/httpsign/ecdsa",
   },
}
