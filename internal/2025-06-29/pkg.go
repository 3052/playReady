package ecdsa

// https://pkg.go.dev/search?limit=100&q=ecdsa

var Pkg = []struct {
   go_sum int
   issue string
   spec   string
}{
   {
      issue: "D deprecated",
      spec:  "crypto/ecdsa",
   },
   {
      issue: "secp256k1 only",
      spec:  "github.com/decred/dcrd/dcrec",
   },
   {
      go_sum: 10,
      spec:  "github.com/btcsuite/btcd/btcec/v2/ecdsa",
   },
   {
      go_sum: 230,
      spec:  "github.com/cosmos/cosmos-sdk/crypto/keys/secp256r1",
   },
   {
      spec:  "github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa",
   },
   /*
   ecdsa (github.com/ldclabs/cose/key/ecdsa)
   Package ecdsa implements signature algorithm ECDSA for COSE as defined in RFC9053.
   Imported by 0
   | v1.3.2 published on Sep 29, 2024 | MIT

   id (github.com/renproject/id)
   Imported by 42
   | v0.4.2 published on Jun 19, 2020 | MIT

   ecdsa (github.com/hellobchain/newcryptosm/ecdsa)
   Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-3.
   Imported by 17
   | v0.0.0-...-edb949a published on Oct 19, 2022 | Apache-2.0

   ecc (github.com/dustinxie/ecc)
   Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-3.
   Imported by 36
   | v0.0.0-...-9595441 published on May 11, 2021 | MIT

   keygen (github.com/bnb-chain/tss-lib/v2/ecdsa/keygen)
   Imported by 18
   | v2.0.2 published on Jan 16, 2024 | MIT
   Other major versions: v1
   Other packages in module github.com/bnb-chain/tss-lib/v2:
   ecdsa/signing
   ecdsa/resharing

   ecdsa (github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa)
   Package ecdsa provides ECDSA signature scheme on the secp256k1 curve.
   Imported by 10
   | v0.18.0 published on Jun 9, 2025 | Apache-2.0
   Other packages in module github.com/consensys/gnark-crypto:
   ecc/stark-curve/ecdsa
   ecc/bls12-377/ecdsa
   ecc/bls12-381/ecdsa
   ecc/bls24-315/ecdsa
   ecc/bls24-317/ecdsa
   +5 more

   ecdsa (github.com/ltcsuite/ltcd/btcec/v2/ecdsa)
   Imported by 28
   | v2.3.2 published on Jan 31, 2024 | ISC

   neofsecdsa (github.com/epicchainlabs/epicchain-sdk-go/crypto/ecdsa)
   Package neofsecdsa collects ECDSA primitives for NeoFS cryptography.
   Imported by 12
   | v0.0.0-...-bb55e7d published on Dec 9, 2024 | Apache-2.0

   ecdsa (github.com/consensys/gnark/std/signature/ecdsa)
   Package ecdsa implements ECDSA signature verification over any elliptic curve.
   Imported by 9
   | v0.13.0 published on Jun 12, 2025 | Apache-2.0

   ecdsa (github.com/PaddlePaddle/PaddleDTX/crypto/core/ecdsa)
   Imported by 25
   | v0.0.0-...-fd327ab published on Aug 22, 2024 | Apache-2.0

   ecdsa (github.com/taurusgroup/multi-party-sig/pkg/ecdsa)
   GO-2024-3288
   Imported by 24
   | v0.7.0-alpha-2025-01-28 published on Jan 28, 2025 | Apache-2.0

   frostfsecdsa (github.com/TrueCloudLab/frostfs-sdk-go/crypto/ecdsa)
   Package frostfsecdsa collects ECDSA primitives for FrostFS cryptography.
   Imported by 11
   | v0.0.0-...-5e759bf published on Mar 1, 2023 | Apache-2.0

   ecdsa (github.com/kubernetes/dashboard/src/app/backend/cert/ecdsa)
   Imported by 52
   | v1.10.1 published on Dec 21, 2018 | Apache-2.0

   ecdsa (github.com/MrLinnea/EEE/btcec/v2/ecdsa)
   Imported by 20
   | v2.0.0-...-28fbc43 published on Sep 9, 2023 | ISC

   frostfsecdsa (git.frostfs.info/TrueCloudLab/frostfs-sdk-go/crypto/ecdsa)
   Package frostfsecdsa collects ECDSA primitives for FrostFS cryptography.
   Imported by 9
   | v0.0.0-...-81815db published on Jun 16, 2025 | Apache-2.0

   signed (github.com/privacybydesign/gabi/signed)
   Package signed contains (1) convenience functions for ECDSA private and public key handling, and for signing and verifying byte slices with ECDSA; (2) functions for marshaling structs to signed bytes, and verifying and unmarshaling signed bytes back to structs.
   Imported by 9
   | v0.0.0-...-202feaa published on Feb 22, 2024 | BSD-3-Clause

   envelope (github.com/libsv/go-bk/envelope)
   Package envelope supports the JSON Envelope Spec It can be found here https://github.com/bitcoin-sv-specs/brfc-misc/tree/master/jsonenvelope Standard for serialising a JSON document in order to have consistency when ECDSA signing the document.
   Imported by 15
   | v0.1.6 published on Dec 15, 2021 | ISC

   id (github.com/muirglacier/id)
   Imported by 14
   | v0.4.5 published on Dec 11, 2021 | MIT

   ecdsa (github.com/prysmaticlabs/prysm/v5/crypto/ecdsa)
   Imported by 1
   | v5.3.3 published on Apr 9, 2025 | GPL-3.0
   Other major versions: v4, v3

   ecdsa (github.com/ProtonMail/go-crypto/openpgp/ecdsa)
   Package ecdsa implements ECDSA signature, suitable for OpenPGP, as specified in RFC 6637, section 5.
   Imported by 5
   | v1.3.0 published on May 22, 2025 | BSD-3-Clause
   Other major versions: v2

   ecdsa (github.com/meshplus/bitxhub-kit/crypto/asym/ecdsa)
   Imported by 13
   | v1.28.0 published on Jan 19, 2023 | LGPL-3.0
   Other packages in module github.com/meshplus/bitxhub-kit:
   crypto/asym/ecdsa/secp256k1

   ecdsa (github.com/primefactor-io/ecc/pkg/ecdsa)
   Package ecdsa implements the Elliptic Curve Digital Signature Algorithm (ECDSA) as well as its adaptor variant as described in section "5.1 ECDSA-based Adaptor Signature" of the paper https://eprint.iacr.org/2020/476.pdf.
   Imported by 4
   | v0.0.0-...-59dd02a published on May 11, 2025 | Apache-2.0

   alg_ecdsa (github.com/common-fate/httpsig/alg_ecdsa)
   Package alg_ecdsa provides a signers and verifiers for ecdsa-p256-sha256 and ecdsa-p384-sha384
   Imported by 4
   | v0.2.1 published on Nov 12, 2024 | MIT

   ecdsa (github.com/FISCO-BCOS/crypto/ecdsa)
   Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-3.
   Imported by 12
   | v0.0.0-...-bd8ab0b published on Feb 2, 2020 | BSD-3-Clause

   ecdsa (github.com/EXCCoin/exccd/dcrec/secp256k1/v4/ecdsa)
   Package ecdsa provides secp256k1-optimized ECDSA signing and verification.
   Imported by 4
   | v4.0.0-...-f9146c5 published on Jun 20, 2024 | ISC

   ecdsa (github.com/Decred-Next/dcrnd/dcrec/secp256k1/version4/v8/ecdsa)
   Package ecdsa provides secp256k1-optimized ECDSA signing and verification.
   Imported by 3
   | v8.0.12 published on Jun 27, 2022 | ISC

   ecdsa (github.com/sebitt27/dcrd/dcrec/secp256k1/v4/ecdsa)
   Package ecdsa provides secp256k1-optimized ECDSA signing and verification.
   Imported by 3
   | v4.0.0-...-e8e7bc6 published on Oct 30, 2023 | ISC

   privatekey (github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey)
   Imported by 8
   | v2.0.0 published on Jan 20, 2023 | MIT
   Other packages in module github.com/starkbank/ecdsa-go/v2:
   ellipticcurve/ecdsa
   ellipticcurve/signature
   ellipticcurve/curve
   ellipticcurve/publickey

   keygen (gitlab.com/thorchain/tss/tss-lib/ecdsa/keygen)
   Imported by 7
   | v0.2.0 published on Feb 8, 2024 | MIT
   Other packages in module gitlab.com/thorchain/tss/tss-lib:
   ecdsa/signing

   keygen (github.com/ordinox/thorchain-tss-lib/ecdsa/keygen)
   Imported by 7
   | v0.0.0-...-f2ec0f2 published on Jun 16, 2024 | MIT
   Other packages in module github.com/ordinox/thorchain-tss-lib:
   ecdsa/signing

   signing (github.com/sodiumlabs/tss-lib/ecdsa/signing)
   Imported by 7
   | v0.0.0-...-80b9cc1 published on Mar 19, 2023 | MIT
   Other packages in module github.com/sodiumlabs/tss-lib:
   ecdsa/keygen

   sign (github.com/xuperchain/crypto/core/sign)
   Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-3.
   Imported by 7
   | v0.0.0-...-ea90456 published on Jul 28, 2023 | Apache-2.0
   Other packages in module github.com/xuperchain/crypto:
   gm/sign

   keygen (github.com/zeta-chain/tss-lib/ecdsa/keygen)
   Imported by 7
   | v0.1.7 published on Oct 27, 2023 | MIT
   Other packages in module github.com/zeta-chain/tss-lib:
   ecdsa/signing

   ecdsa_go_proto (github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto)
   Imported by 6
   | v2.4.0 published on Apr 2, 2025 | Apache-2.0
   Other packages in module github.com/tink-crypto/tink-go/v2:
   signature/ecdsa
   proto/jwt_ecdsa_go_proto

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

   jwtkey (github.com/stellar/go/exp/support/jwtkey)
   Package jwtkey provides utility functions for generating, serializing and deserializing JWT ECDSA keys.
   Imported by 5
   | v0.0.0-...-032c5f9 published on 2 days ago | Apache-2.0

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

   ecdsa (github.com/starainrt/go-crypto/openpgp/ecdsa)
   Package ecdsa implements ECDSA signature, suitable for OpenPGP, as specified in RFC 6637, section 5.
   Imported by 1
   | v0.0.0-...-3b746eb published on today | BSD-3-Clause

   ecdsa (github.com/amitkgupta/go-smarthealthcards/v2/ecdsa)
   Package ecdsa loads an ECDSA P-256 private key (*crypto/ecdsa.PrivateKey) from string representations of its key parameters.
   Imported by 1
   | v2.0.1 published on Dec 5, 2021 | MIT
   Other major versions: v1
   Other packages in module github.com/amitkgupta/go-smarthealthcards/v2:
   jws

   ecdsa (github.com/moolekkari/go-crypto/openpgp/ecdsa)
   Package ecdsa implements ECDSA signature, suitable for OpenPGP, as specified in RFC 6637, section 5.
   Imported by 1
   | v0.0.0-...-4b32916 published on Dec 12, 2024 | BSD-3-Clause

   ecdsa (github.com/bb-Ricardo/go-crypto/openpgp/ecdsa)
   Package ecdsa implements ECDSA signature, suitable for OpenPGP, as specified in RFC 6637, section 5.
   Imported by 1
   | v0.0.0-...-bb554c2 published on Dec 12, 2022 | BSD-3-Clause

   ecdsa (github.com/rohautl/go-crypto/openpgp/ecdsa)
   Package ecdsa implements ECDSA signature, suitable for OpenPGP, as specified in RFC 6637, section 5.
   Imported by 1
   | v0.0.0-...-e7fc477 published on Sep 26, 2022 | BSD-3-Clause

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

   tokenauth (github.com/gobuffalo/mw-tokenauth)
   Package tokenauth provides jwt token authorisation middleware supports HMAC, RSA, ECDSA, RSAPSS EdDSA algorithms uses github.com/golang-jwt/jwt/v4 for jwt implementation
   Imported by 2
   | v1.0.2 published on Feb 15, 2023 | MIT

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

   ecdsa (gopkg.in/zhevron/jwt.v1/ecdsa)
   Package ecdsa provides ECDSA signing methods for JWT.
   Imported by 1
   | v1.0.0-...-79c4aa1 published on Apr 15, 2015 | MIT

   ecdsa (github.com/PutinCoinPUT/ppcd/btcec/ecdsa)
   Imported by 3
   | v0.0.0-...-3ecc070 published on Jan 31, 2024 | MIT

   ecdsa (go.gnd.pw/crypto/openpgp/ecdsa)
   Package ecdsa implements ECDSA signature, suitable for OpenPGP, as specified in RFC 6637, section 5.
   Imported by 0
   | v0.0.0-...-86ae774 published on Nov 18, 2023 | BSD-3-Clause

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

   ecdsa (github.com/Serg-Martyushev/go-crypto/openpgp/ecdsa)
   Package ecdsa implements ECDSA signature, suitable for OpenPGP, as specified in RFC 6637, section 5.
   Imported by 0
   | v0.0.0-...-b1f8521 published on Aug 8, 2024 | BSD-3-Clause

   jwkgen (github.com/glamorouscub/jwkgen)
   command
   Imported by 0
   | v0.0.0-...-d06e9d8 published on Feb 27, 2025 | MIT
   */
}

var Pkg_old = []struct {
   issue string
   note  string
   spec   string
}{
   {
      note: "github.com/renproject/id/blob/master/go.sum",
      spec:  "github.com/renproject/id",
   },
   {
      note: "github.com/hellobchain/newcryptosm/blob/main/go.sum",
      spec:  "github.com/hellobchain/newcryptosm/ecdsa",
   },
   {
      note: "secp256k1 is not compatible with secp256r1",
      spec:  "github.com/dustinxie/ecc",
   },
   {
      note: "github.com/bnb-chain/tss-lib/blob/master/go.sum",
      spec:  "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen",
   },
   {
      note: "github.com/Consensys/gnark-crypto/blob/master/go.sum",
      spec:  "github.com/consensys/gnark-crypto/ecc",
   },
   {
      note: "github.com/ltcsuite/ltcd/blob/master/btcec/go.sum",
      spec:  "github.com/ltcsuite/ltcd/btcec/v2/ecdsa",
   },
   {
      note: "github.com/epicchainlabs/epicchain-sdk-go/blob/main/go.sum",
      spec:  "github.com/epicchainlabs/epicchain-sdk-go/crypto/ecdsa",
   },
   {
      note: "github.com/Consensys/gnark/blob/master/go.sum",
      spec:  "github.com/consensys/gnark/std/signature/ecdsa",
   },
   {
      note: "github.com/PaddlePaddle/PaddleDTX/blob/master/crypto/go.sum",
      spec:  "github.com/PaddlePaddle/PaddleDTX/crypto/core/ecdsa",
   },
   {
      note: "github.com/taurushq-io/multi-party-sig/blob/main/go.sum",
      spec:  "github.com/taurusgroup/multi-party-sig/pkg/ecdsa",
   },
   {
      note: "github.com/TrueCloudLab/frostfs-sdk-go/blob/master/go.sum",
      spec:  "github.com/TrueCloudLab/frostfs-sdk-go/crypto/ecdsa",
   },
   {
      note: "github.com/kubernetes/dashboard/blob/master/modules/common/certificates/go.sum",
      spec:  "github.com/kubernetes/dashboard/src/app/backend/cert/ecdsa",
   },
   {
      note: "404 github.com/MrLinnea/EEE",
      spec:  "github.com/MrLinnea/EEE/btcec/v2/ecdsa",
   },
   {
      note: "github.com/privacybydesign/gabi/blob/master/go.sum",
      spec:  "github.com/privacybydesign/gabi/signed",
   },
   {
      note: "git.frostfs.info/TrueCloudLab/frostfs-sdk-go/src/branch/master/go.sum",
      spec:  "git.frostfs.info/TrueCloudLab/frostfs-sdk-go/crypto/ecdsa",
   },
   {
      note: "github.com/libsv/go-bk/blob/master/go.sum",
      spec:  "github.com/libsv/go-bk/envelope",
   },
   {
      note: "github.com/OffchainLabs/prysm/blob/develop/go.sum",
      spec:  "github.com/prysmaticlabs/prysm/v5/crypto/ecdsa",
   },
   {
      note: "github.com/muirglacier/id/blob/master/go.sum",
      spec:  "github.com/muirglacier/id",
   },
   {
      issue: "github.com/ProtonMail/go-crypto/issues/289",
      note: "openpgp/internal/ecc: deprecated items",
      spec:  "github.com/ProtonMail/go-crypto/openpgp/ecdsa",
   },
   {
      note: "github.com/meshplus/bitxhub-kit/blob/master/go.sum",
      spec: "github.com/meshplus/bitxhub-kit/crypto/asym/ecdsa",
   },
   {
      note: "requires crypto/ecdsa",
      spec: "github.com/common-fate/httpsig/alg_ecdsa",
   },
   {
      note: "secp256r1",
      issue: "github.com/primefactor-io/ecc/issues/1",
      spec: "github.com/primefactor-io/ecc/pkg/ecdsa",
   },
   {
      note: "requires crypto/elliptic.Curve.ScalarBaseMult",
      spec: "github.com/FISCO-BCOS/crypto/ecdsa",
   },
   {
      note: "secp256k1 only",
      spec: "github.com/EXCCoin/exccd/dcrec",
   },
   {
      note: "secp256k1 only",
      spec: "github.com/Decred-Next/dcrnd/dcrec",
   },
   {
      note: "secp256k1 only",
      spec: "github.com/sebitt27/dcrd/dcrec",
   },
   {
      note: "PASS github.com/starkbank/ecdsa-go/blob/master/go.mod",
      spec: "github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa",
   },
   {
      note: "404 github.com/sodiumlabs/tss-lib",
      spec: "github.com/sodiumlabs/tss-lib",
   },
   {
      note: "weird",
      spec: "github.com/zeta-chain/tss-lib/ecdsa/signing",
   },
   {
      note: "weird",
      spec: "github.com/ordinox/thorchain-tss-lib/ecdsa/signing",
   },
   {
      note: "github.com/xuperchain/crypto/blob/master/go.sum",
      spec: "github.com/xuperchain/crypto",
   },
   {
      note: "gitlab.com/thorchain/tss/tss-lib/-/blob/master/go.sum",
      spec: "gitlab.com/thorchain/tss/tss-lib/ecdsa/signing",
   },
   {
      note: "fucking stupid",
      spec: "github.com/tink-crypto/tink-go/v2/signature/ecdsa",
   },
   {
      note: "secp256k1 only",
      spec: "github.com/multicash/mcxd/mcxec",
   },
   {
      note: "secp256k1 only",
      spec: "github.com/Decred-Next/dcrnd/dcrec",
   },
   {
      note: "github.com/AVecsi/pq-gabi/blob/master/go.sum",
      spec: "github.com/AVecsi/pq-gabi/signed",
   },
   {
      note: "github.com/libp2p/go-libp2p/blob/master/go.sum",
      spec: "github.com/libp2p/go-libp2p/core/crypto",
   },
   {
      note: "uses crypto/ecdsa",
      spec: "github.com/libs4go/crypto/ecdsa",
   },
   {
      note: "github.com/Layr-Labs/eigensdk-go/blob/dev/go.sum",
      spec: "github.com/Layr-Labs/eigensdk-go/crypto/ecdsa",
   },
   {
      note: "fucking stupid",
      spec: "github.com/sonr-io/multi-party-sig/pkg/ecdsa",
   },
   {
      note: "git.chainmaker.org.cn/chainmaker/common/-/blob/master/go.sum",
      spec: "chainmaker.org/chainmaker/common/v3/crypto/asym/ecdsa",
   },
   {
      note: "ScalarBaseMult is deprecated",
      issue: "github.com/cloudflare/pat-go/issues/61",
      spec: "github.com/cloudflare/pat-go/ecdsa",
   },
   {
      note: "crypto/ecdsa need way to generate PrivateKey from bytes",
      issue: "github.com/runZeroInc/excrypto/issues/37",
      spec: "github.com/runZeroInc/excrypto/crypto/ecdsa",
   },
   {
      note: "ECDSA key from bytes",
      issue: "github.com/svicknesh/key/issues/1",
      spec: "github.com/svicknesh/key/v2",
   },
   {
      note: "ecdsa: need way to generate PrivateKey from bytes",
      issue: "github.com/A1andNS/newCrypto/issues/1",
      spec: "https://github.com/A1andNS/newCrypto/ecdsa",
   },
   {
      note: "weird",
      spec: "github.com/okx/threshold-lib/tss/ecdsa/sign",
   },
   {
      note: "github.com/flokiorg/go-flokicoin/blob/main/go.sum",
      spec: "github.com/flokiorg/go-flokicoin/crypto/ecdsa",
   },
   {
      note: "no sign",
      spec: "github.com/0xPellNetwork/pelldvs-libs/crypto/ecdsa",
   },
   {
      note: "github.com/opzlabs/cosmos-sdk-terra3/blob/main/go.sum",
      spec: "github.com/opzlabs/cosmos-sdk-v0.46.13-terra.3/crypto/keys/secp256r1",
   },
   {
      note: "no sign",
      spec: "gitlab.com/alephledger/threshold-ecdsa/pkg",
   },
   {
      note: "old",
      spec: "github.com/GM-Publicchain/gm/plugin/crypto/ecdsa",
   },
   {
      note: "archived",
      spec: "github.com/keep-network/keep-ecdsa/pkg/ecdsa",
   },
   {
      note: "go.mod",
      issue: "github.com/PutinCoinPUT/ppcd/issues/1",
      spec: "github.com/PutinCoinPUT/ppcd/btcec/ecdsa",
   },
   {
      note: "EccFrog512CK2 elliptic curve",
      spec: "github.com/shovon/go-eccfrog512ck2/ecc/ecdsa",
   },
   {
      note: "publish",
      spec: "github.com/shovon/elliptic-curve-pointless/issues/1",
   },
   {
      note: "ECDSA import key raw",
      issue: "github.com/armortal/webcrypto-go/issues/39",
      spec: "github.com/armortal/webcrypto-go/algorithms/ecdsa",
   },
   {
      note: "github.com/BeratOz01/gnark/blob/master/go.sum",
      spec: "github.com/BeratOz01/gnark/std/signature/ecdsa",
   },
   {
      note: "fork",
      spec: "github.com/Overclock-Validator/gnark-crypto/ecc",
   },
   {
      note: "uses crypto/ecdsa",
      spec: "github.com/denpeshkov/httpsign/ecdsa",
   },
}
