import ctypes

from zksync.sdk.musig.schnorr_musig_native import *


class TestSchnorrMusigNative:
    PUBLIC_KEY = [23, -100, 58, 89, 20, 125, 48, 49, 108, -120, 102, 40, -123, 35, 72, -55, -76, 42, 24, -72, 33, 8, 74,
                  -55, -17, 121, -67, 115, -23, -71, 78, -115]
    PRIVATE_KEY = [1, 31, 91, -103, 8, 76, 92, 46, 45, 94, 99, 72, -114, 15, 113, 104, -43, -103, -91, -64, 31, -23, -2,
                   -60, -55, -106, 5, 116, 61, -91, -24, 92]
    SEED = [16807, 282475249, 1622650073, 984943658]

    MESSAGE = 'hello'.encode()

    def test_load_c_library(self):
        musig = SchnorrMusigLoader.load()
        assert musig

    def test_schnorr_musig_new_signer(self):
        musig = SchnorrMusigLoader.load()
        singer = TestSchnorrMusigNative.create_signer(musig)
        assert singer
        assert singer.contents.inner

    def test_schnorr_musig_delete_signer(self):
        musig = SchnorrMusigLoader.load()
        singer = TestSchnorrMusigNative.create_signer(musig)
        musig.schnorr_musig_delete_signer(singer)

    def test_schnorr_musig_aggregate_pubkeys(self):
        musig = SchnorrMusigLoader.load()
        public_keys = [
            [23, -100, 58, 89, 20, 125, 48, 49, 108, -120, 102, 40, -123, 35, 72, -55, -76, 42, 24, -72, 33, 8, 74, -55,
             -17, 121, -67, 115, -23, -71, 78, -115],
            [10, -12, -71, -92, -23, -30, -75, -92, -44, -48, -90, -46, -21, -102, -15, -102, -67, -99, -116, 95, 0,
             -101, 80, -13, -47, 95, -86, 126, 112, 100, -10, -97],
            [-50, -81, -40, -53, 21, -95, 0, -25, -83, 13, -29, -41, 63, 125, -52, -24, -71, -29, 36, 60, -73, -37, -42,
             78, 59, 11, 10, 121, -102, -109, -77, -120],
            [63, 6, 62, -21, 40, -71, 18, -96, 89, -4, -118, -116, 100, 33, -20, 89, -51, 45, -113, 42, 25, 64, 43, 9,
             125, 120, -33, -118, 56, 100, -9, 15],
            [40, 107, 64, 71, 20, -37, -122, 117, 29, -110, 92, 118, -49, 119, 7, 9, -105, -28, -120, 101, -100, 74,
             -65, 116, -52, 114, -102, 55, 17, -68, 27, -92]
        ]

        joint_public_keys = []
        for publicKey in public_keys:
            joint_public_keys += publicKey
        joint_public_keys_len = len(joint_public_keys)

        aggregated_public_key = AggregatedPublicKey()
        code = musig.schnorr_musig_aggregate_pubkeys((c_ubyte * joint_public_keys_len)(*joint_public_keys),
                                                     c_size_t(joint_public_keys_len),
                                                     AggregatedPublicKeyPointer(aggregated_public_key))
        assert code is not None
        assert code == MusigRes.OK
        assert aggregated_public_key.data

    def test_schnorr_musig_compute_precommitment(self):
        musig = SchnorrMusigLoader.load()
        singer = TestSchnorrMusigNative.create_signer(musig)
        precommitment = TestSchnorrMusigNative.create_precommitment(musig, singer)

        assert precommitment
        assert precommitment.data
        assert '93ae6e6df739d76c088755078ed857e95119909c97bdd5cdc8aa12286abc0984' == bytearray(precommitment.data).hex()

    def test_schnorr_musig_receive_precommitments(self):
        musig = SchnorrMusigLoader.load()
        singer = TestSchnorrMusigNative.create_signer(musig)
        precommitment = TestSchnorrMusigNative.create_precommitment(musig, singer)

        aggregated_data_len = len(precommitment.data)
        aggregated_data = (c_ubyte * aggregated_data_len)()
        ctypes.memmove(aggregated_data, precommitment.data, aggregated_data_len)

        commitment = Commitment()
        code = musig.schnorr_musig_receive_precommitments(singer, aggregated_data, c_size_t(aggregated_data_len),
                                                          CommitmentPointer(commitment))

        assert code is not None
        assert code == MusigRes.OK
        assert 'a18005f171a323d022a625e71aa53864ca6d1851a1fc50585b7627fba3f6c69f' == bytearray(commitment.data).hex()

    def test_schnorr_musig_receive_commitments(self):
        musig = SchnorrMusigLoader.load()
        singer = TestSchnorrMusigNative.create_signer(musig)
        precommitment = TestSchnorrMusigNative.create_precommitment(musig, singer)

        aggregated_data_len = len(precommitment.data)
        aggregated_data = (c_ubyte * aggregated_data_len)()
        ctypes.memmove(aggregated_data, precommitment.data, aggregated_data_len)

        commitment = Commitment()
        code = musig.schnorr_musig_receive_precommitments(singer, aggregated_data, c_size_t(aggregated_data_len),
                                                          CommitmentPointer(commitment))
        assert code == MusigRes.OK

        aggregated_commitment_data_len = len(commitment.data)
        aggregated_commitment_data = (c_ubyte * aggregated_commitment_data_len)()
        ctypes.memmove(aggregated_commitment_data, commitment.data, aggregated_commitment_data_len)
        aggregated_commitment = AggregatedCommitment()

        code = musig.schnorr_musig_receive_commitments(singer, aggregated_commitment_data,
                                                       aggregated_commitment_data_len,
                                                       AggregatedCommitmentPointer(aggregated_commitment))

        assert code is not None
        assert code == MusigRes.OK
        assert 'a18005f171a323d022a625e71aa53864ca6d1851a1fc50585b7627fba3f6c69f' == bytearray(
            aggregated_commitment.data).hex()

        signature = TestSchnorrMusigNative.create_signature(musig, singer)
        assert '02bae431c052b9e4f7c9b511904a577c7ba5e035625879d5253440793337f7ff' == bytearray(signature.data).hex()

        aggregated_signature_data_len = len(signature.data)
        aggregated_signature_data = (c_ubyte * aggregated_signature_data_len)()
        ctypes.memmove(aggregated_signature_data, signature.data, aggregated_signature_data_len)
        aggregated_signature = AggregatedSignature()
        code = musig.schnorr_musig_receive_signature_shares(singer, aggregated_signature_data,
                                                            aggregated_signature_data_len,
                                                            AggregatedSignaturePointer(aggregated_signature))

        assert code is not None
        assert code == MusigRes.OK

        message = TestSchnorrMusigNative.MESSAGE
        message_len = len(message)
        public_key = TestSchnorrMusigNative.PUBLIC_KEY
        public_key_len = len(public_key)

        code = musig.schnorr_musig_verify((c_ubyte * message_len)(*message), c_size_t(message_len),
                                          (c_ubyte * public_key_len)(*public_key), c_size_t(public_key_len),
                                          aggregated_signature.data, c_size_t(len(aggregated_signature.data)))

        assert code is not None
        assert code == MusigRes.OK

    @staticmethod
    def create_signer(musig: SchnorrMusigNative) -> MusigSignerPointer:
        public_key = TestSchnorrMusigNative.PUBLIC_KEY
        public_key_len = len(public_key)
        position = 0
        return musig.schnorr_musig_new_signer((c_ubyte * public_key_len)(*public_key), c_size_t(len(public_key)),
                                              c_size_t(position))

    @staticmethod
    def create_precommitment(musig: SchnorrMusigNative, singer: MusigSignerPointer) -> Precommitment:
        seed = TestSchnorrMusigNative.SEED
        seed_len = len(seed)
        precommitment = Precommitment()
        code = musig.schnorr_musig_compute_precommitment(singer, (c_uint32 * seed_len)(*seed), c_size_t(seed_len),
                                                         PrecommitmentPointer(precommitment))
        assert code is not None
        assert code == MusigRes.OK
        return precommitment

    @staticmethod
    def create_signature(musig: SchnorrMusigNative, singer: MusigSignerPointer):
        private_key = TestSchnorrMusigNative.PRIVATE_KEY
        private_key_len = len(private_key)
        message = TestSchnorrMusigNative.MESSAGE
        message_len = len(message)

        signature = Signature()
        code = musig.schnorr_musig_sign(singer, (c_ubyte * private_key_len)(*private_key), c_size_t(private_key_len),
                                        (c_ubyte * message_len)(*message), c_size_t(message_len),
                                        SignaturePointer(signature))
        assert code is not None
        assert code == MusigRes.OK
        return signature
