from zksync.sdk.musig.schnorr_musig import SchnorrMusig


class TestSchnorrMusig:
    SEED = bytes.fromhex('a7410000f13ad610d9acb7602a0cb53a')
    MSG = 'hello'.encode()

    def test_single(self):
        private_key = bytes.fromhex('011f5b99084c5c2e2d5e63488e0f7168d599a5c01fe9fec4c99605743da5e85c')
        public_key = bytes.fromhex('179c3a59147d30316c886628852348c9b42a18b821084ac9ef79bd73e9b94e8d')

        musig = SchnorrMusig()
        signer = musig.create_signer_from_key(public_key)
        precommitment = signer.compute_precommitment(TestSchnorrMusig.SEED)
        assert '93ae6e6df739d76c088755078ed857e95119909c97bdd5cdc8aa12286abc0984' == bytes(precommitment.data).hex()

        commitment = signer.receive_precommitments(precommitment)
        assert 'a18005f171a323d022a625e71aa53864ca6d1851a1fc50585b7627fba3f6c69f' == bytes(commitment.data).hex()

        aggregated_commitment = signer.receive_commitments(commitment)
        assert 'a18005f171a323d022a625e71aa53864ca6d1851a1fc50585b7627fba3f6c69f' == bytes(
            aggregated_commitment.data).hex()

        signature = signer.sign(private_key, TestSchnorrMusig.MSG)
        assert '02bae431c052b9e4f7c9b511904a577c7ba5e035625879d5253440793337f7ff' == bytes(signature.data).hex()

        aggregate_signature = signer.aggregate_signature(signature)
        assert musig.verify_by_public_keys(TestSchnorrMusig.MSG, aggregate_signature, public_key)

    def test_multiple(self):
        musig = SchnorrMusig()
        private_keys = ['011f5b99084c5c2e2d5e63488e0f7168d599a5c01fe9fec4c99605743da5e85c',
                        '05befa1dc5beb8aa74c348966f5254702bc0a9613e519eb3ef2fe8c444f40d33',
                        '03cd8947a90f73a875623574f8e0e3d3c6abd8f9367ba54433ed02b7a62533d9',
                        '02556c232cfb6c8274ac7e2e55fe1f87b6dee119bf62a3c784102de6c25c2512',
                        '01791089b53bee682147ecbc5e26325329a21c894a6205876c58798d1c268ae4']

        public_keys = ['179c3a59147d30316c886628852348c9b42a18b821084ac9ef79bd73e9b94e8d',
                       '0af4b9a4e9e2b5a4d4d0a6d2eb9af19abd9d8c5f009b50f3d15faa7e7064f69f',
                       'ceafd8cb15a100e7ad0de3d73f7dcce8b9e3243cb7dbd64e3b0b0a799a93b388',
                       '3f063eeb28b912a059fc8a8c6421ec59cd2d8f2a19402b097d78df8a3864f70f',
                       '286b404714db86751d925c76cf77070997e488659c4abf74cc729a3711bc1ba4']

        public_keys = [bytes.fromhex(key) for key in public_keys]
        private_keys = [bytes.fromhex(key) for key in private_keys]

        all_public_keys = bytes()
        for publicKey in public_keys:
            all_public_keys += publicKey

        signers = []
        for index in range(len(public_keys)):
            signers.append(musig.create_signer_from_encoded_keys(all_public_keys, index))

        precommitments = []
        for signer in signers:
            precommitments.append(signer.compute_precommitment(TestSchnorrMusig.SEED))

        commitments = []
        for signer in signers:
            commitments.append(signer.receive_precommitments(*precommitments))

        aggregated_commitments = []
        for signer in signers:
            aggregated_commitments.append(signer.receive_commitments(*commitments))

        signatures = []
        for index in range(len(public_keys)):
            signatures.append(signers[index].sign(private_keys[index], TestSchnorrMusig.MSG))

        aggregated_signatures = []
        for signer in signers:
            aggregated_signatures.append(signer.aggregate_signature(*signatures))

        for signature in aggregated_signatures:
            assert [*aggregated_signatures[0].data] == [*signature.data]

        assert musig.verify_by_public_keys(TestSchnorrMusig.MSG, aggregated_signatures[0], all_public_keys)

        aggregated_public_key = musig.aggregate_public_keys(all_public_keys)
        assert musig.verify_by_agg_public_key(TestSchnorrMusig.MSG, aggregated_signatures[0], aggregated_public_key)
