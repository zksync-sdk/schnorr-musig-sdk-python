from typing import List

from zksync.sdk.musig.schnorr_musig_error import SchnorrMusigError
from zksync.sdk.musig.schnorr_musig_native import *


class SchnorrMusigSigner:

    def __init__(self, musig: SchnorrMusigNative, signer: MusigSignerPointer, public_key: List[int]) -> None:
        self.musig = musig
        self.signer = signer
        self.public_key = public_key

    def sign(self, private_key: List[int], message: List[int]) -> Signature:
        private_key_len = len(private_key)
        message_len = len(message)

        signature = Signature()
        code = self.musig.schnorr_musig_sign(self.signer, (c_ubyte * private_key_len)(*private_key),
                                             c_size_t(private_key_len), (c_ubyte * message_len)(*message),
                                             c_size_t(message_len), SignaturePointer(signature))
        if code != MusigRes.OK:
            raise SchnorrMusigError(code)

        return signature

    def compute_precommitment(self, seed: List[int]) -> Precommitment:
        seed_len = len(seed)
        precommitment = Precommitment()
        code = self.musig.schnorr_musig_compute_precommitment(self.signer, (c_uint32 * seed_len)(*seed),
                                                              c_size_t(seed_len), PrecommitmentPointer(precommitment))

        if code != MusigRes.OK:
            raise SchnorrMusigError(code)

        return precommitment

    def receive_precommitments(self, *precommitments: Precommitment) -> Commitment:
        precommitments_data = []
        for precommitment in precommitments:
            precommitments_data += [*precommitment.data]
        precommitments_data_len = len(precommitments_data)


        commitment = Commitment()
        code = self.musig.schnorr_musig_receive_precommitments(self.signer, (c_ubyte * precommitments_data_len)(
            *precommitments_data), c_size_t(precommitments_data_len), CommitmentPointer(commitment))

        if code != MusigRes.OK:
            raise SchnorrMusigError(code)

        return commitment

    def receive_commitments(self, *commitments: Commitment) -> AggregatedCommitment:
        commitments_data = []
        for commitment in commitments:
            commitments_data += [*commitment.data]
        commitments_data_len = len(commitments_data)

        aggregated_commitment = AggregatedCommitment()
        code = self.musig.schnorr_musig_receive_commitments(self.signer,
                                                            (c_ubyte * commitments_data_len)(*commitments_data),
                                                            c_size_t(commitments_data_len),
                                                            AggregatedCommitmentPointer(aggregated_commitment))

        if code != MusigRes.OK:
            raise SchnorrMusigError(code)

        return aggregated_commitment

    def aggregate_signature(self, *signatures: Signature) -> AggregatedSignature:
        signatures_data = []
        for signature in signatures:
            signatures_data += [*signature.data]
        signatures_data_len = len(signatures_data)

        aggregated_signature = AggregatedSignature()
        code = self.musig.schnorr_musig_receive_signature_shares(self.signer,
                                                                 (c_ubyte * signatures_data_len)(*signatures_data),
                                                                 c_size_t(signatures_data_len),
                                                                 AggregatedSignaturePointer(aggregated_signature))

        if code != MusigRes.OK:
            raise SchnorrMusigError(code)

        return aggregated_signature

    def revoke(self):
        self.musig.schnorr_musig_delete_signer(self.signer)
