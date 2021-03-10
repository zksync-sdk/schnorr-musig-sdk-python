import ctypes

from zksync.sdk.musig.schnorr_musig_native import *


class TestSchnorrMusigNative:
    PUBLIC_KEY = bytes.fromhex('179c3a59147d30316c886628852348c9b42a18b821084ac9ef79bd73e9b94e8d')
    PRIVATE_KEY = bytes.fromhex('011f5b99084c5c2e2d5e63488e0f7168d599a5c01fe9fec4c99605743da5e85c')
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
        public_keys = ['179c3a59147d30316c886628852348c9b42a18b821084ac9ef79bd73e9b94e8d',
                       '0af4b9a4e9e2b5a4d4d0a6d2eb9af19abd9d8c5f009b50f3d15faa7e7064f69f',
                       'ceafd8cb15a100e7ad0de3d73f7dcce8b9e3243cb7dbd64e3b0b0a799a93b388',
                       '3f063eeb28b912a059fc8a8c6421ec59cd2d8f2a19402b097d78df8a3864f70f',
                       '286b404714db86751d925c76cf77070997e488659c4abf74cc729a3711bc1ba4']

        public_keys = [bytes.fromhex(key) for key in public_keys]

        joint_public_keys = bytes()
        for publicKey in public_keys:
            joint_public_keys += publicKey

        aggregated_public_key = AggregatedPublicKey()
        code = musig.schnorr_musig_aggregate_pubkeys(joint_public_keys, len(joint_public_keys),
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
        assert '93ae6e6df739d76c088755078ed857e95119909c97bdd5cdc8aa12286abc0984' == bytes(precommitment.data).hex()

    def test_schnorr_musig_receive_precommitments(self):
        musig = SchnorrMusigLoader.load()
        singer = TestSchnorrMusigNative.create_signer(musig)
        precommitment = TestSchnorrMusigNative.create_precommitment(musig, singer)

        aggregated_data_len = len(precommitment.data)
        aggregated_data = (c_ubyte * aggregated_data_len)()
        ctypes.memmove(aggregated_data, precommitment.data, aggregated_data_len)

        commitment = Commitment()
        code = musig.schnorr_musig_receive_precommitments(singer, aggregated_data, aggregated_data_len,
                                                          CommitmentPointer(commitment))

        assert code is not None
        assert code == MusigRes.OK
        assert 'a18005f171a323d022a625e71aa53864ca6d1851a1fc50585b7627fba3f6c69f' == bytes(commitment.data).hex()

    def test_schnorr_musig_receive_commitments(self):
        musig = SchnorrMusigLoader.load()
        singer = TestSchnorrMusigNative.create_signer(musig)
        precommitment = TestSchnorrMusigNative.create_precommitment(musig, singer)

        aggregated_data_len = len(precommitment.data)
        aggregated_data = (c_ubyte * aggregated_data_len)()
        ctypes.memmove(aggregated_data, precommitment.data, aggregated_data_len)

        commitment = Commitment()
        code = musig.schnorr_musig_receive_precommitments(singer, aggregated_data, aggregated_data_len,
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
        assert 'a18005f171a323d022a625e71aa53864ca6d1851a1fc50585b7627fba3f6c69f' == bytes(
            aggregated_commitment.data).hex()

        signature = TestSchnorrMusigNative.create_signature(musig, singer)
        assert '02bae431c052b9e4f7c9b511904a577c7ba5e035625879d5253440793337f7ff' == bytes(signature.data).hex()

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
        public_key = TestSchnorrMusigNative.PUBLIC_KEY

        code = musig.schnorr_musig_verify(message, len(message),
                                          public_key, len(public_key),
                                          aggregated_signature.data, len(aggregated_signature.data))

        assert code is not None
        assert code == MusigRes.OK

    @staticmethod
    def create_signer(musig: SchnorrMusigNative) -> MusigSignerPointer:
        public_key = TestSchnorrMusigNative.PUBLIC_KEY
        position = 0
        return musig.schnorr_musig_new_signer(public_key, len(public_key), position)

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
        message = TestSchnorrMusigNative.MESSAGE

        signature = Signature()
        code = musig.schnorr_musig_sign(singer, private_key, len(private_key), message, len(message),
                                        SignaturePointer(signature))
        assert code is not None
        assert code == MusigRes.OK
        return signature
