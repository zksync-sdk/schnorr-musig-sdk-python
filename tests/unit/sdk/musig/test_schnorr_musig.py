from zksync.sdk.musig.schnorr_musig import SchnorrMusig


class TestSchnorrMusig:
    SEED = [16807, 282475249, 1622650073, 984943658]
    MSG = 'hello'.encode()

    def test_single(self):
        private_key = [1, 31, 91, -103, 8, 76, 92, 46, 45, 94, 99, 72, -114, 15, 113, 104, -43, -103, -91, -64, 31, -23,
                       -2, -60, -55, -106, 5, 116, 61, -91, -24, 92]
        public_key = [23, -100, 58, 89, 20, 125, 48, 49, 108, -120, 102, 40, -123, 35, 72, -55, -76, 42, 24, -72, 33, 8,
                      74, -55, -17, 121, -67, 115, -23, -71, 78, -115]

        musig = SchnorrMusig()
        signer = musig.create_signer_from_key(public_key)
        precommitment = signer.compute_precommitment(TestSchnorrMusig.SEED)
        assert '93ae6e6df739d76c088755078ed857e95119909c97bdd5cdc8aa12286abc0984' == bytearray(precommitment.data).hex()

        commitment = signer.receive_precommitments(precommitment);
        assert 'a18005f171a323d022a625e71aa53864ca6d1851a1fc50585b7627fba3f6c69f' == bytearray(commitment.data).hex()

        aggregated_commitment = signer.receive_commitments(commitment)
        assert 'a18005f171a323d022a625e71aa53864ca6d1851a1fc50585b7627fba3f6c69f' == bytearray(
            aggregated_commitment.data).hex()

        signature = signer.sign(private_key, TestSchnorrMusig.MSG)
        assert '02bae431c052b9e4f7c9b511904a577c7ba5e035625879d5253440793337f7ff' == bytearray(signature.data).hex()

        aggregate_signature = signer.aggregate_signature(signature)
        assert musig.verify_by_public_keys(TestSchnorrMusig.MSG, aggregate_signature, public_key)

    def test_multiple(self):
        musig = SchnorrMusig()
        private_keys = [
            [1, 31, 91, -103, 8, 76, 92, 46, 45, 94, 99, 72, -114, 15, 113, 104, -43, -103, -91, -64, 31, -23, -2, -60,
             -55, -106, 5, 116, 61, -91, -24, 92],
            [5, -66, -6, 29, -59, -66, -72, -86, 116, -61, 72, -106, 111, 82, 84, 112, 43, -64, -87, 97, 62, 81, -98,
             -77, -17, 47, -24, -60, 68, -12, 13, 51],
            [3, -51, -119, 71, -87, 15, 115, -88, 117, 98, 53, 116, -8, -32, -29, -45, -58, -85, -40, -7, 54, 123, -91,
             68, 51, -19, 2, -73, -90, 37, 51, -39],
            [2, 85, 108, 35, 44, -5, 108, -126, 116, -84, 126, 46, 85, -2, 31, -121, -74, -34, -31, 25, -65, 98, -93,
             -57, -124, 16, 45, -26, -62, 92, 37, 18],
            [1, 121, 16, -119, -75, 59, -18, 104, 33, 71, -20, -68, 94, 38, 50, 83, 41, -94, 28, -119, 74, 98, 5, -121,
             108, 88, 121, -115, 28, 38, -118, -28]
        ]

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

        all_public_keys = []
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
        assert musig.verify_by_agg_public_keys(TestSchnorrMusig.MSG, aggregated_signatures[0], aggregated_public_key)
