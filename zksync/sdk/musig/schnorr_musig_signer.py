from zksync.sdk.musig.schnorr_musig_error import SchnorrMusigError
from zksync.sdk.musig.schnorr_musig_native import *


class SchnorrMusigSigner:

    def __init__(self, musig: SchnorrMusigNative, signer: MusigSignerPointer, public_keys: bytes) -> None:
        self.musig = musig
        self.signer = signer
        self.public_keys = public_keys

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        signature = Signature()
        code = self.musig.schnorr_musig_sign(self.signer, private_key, len(private_key), message, len(message),
                                             SignaturePointer(signature))
        if code != MusigRes.OK:
            raise SchnorrMusigError(code)

        return bytes(signature.data)

    def compute_precommitment(self, seed: bytes) -> bytes:
        seed_len = int(len(seed) / 4)
        seed_data = [c_uint32(int.from_bytes(seed[index * 4: index * 4 + 4], byteorder='little')) for index in
                     range(seed_len)]

        precommitment = Precommitment()
        code = self.musig.schnorr_musig_compute_precommitment(
            self.signer, (c_uint32 * seed_len)(*seed_data), seed_len, PrecommitmentPointer(precommitment))

        if code != MusigRes.OK:
            raise SchnorrMusigError(code)

        return bytes(precommitment.data)

    def receive_precommitments(self, *precommitments: bytes) -> bytes:
        precommitments_data = bytes()
        for precommitment in precommitments:
            precommitments_data += precommitment

        commitment = Commitment()
        code = self.musig.schnorr_musig_receive_precommitments(self.signer, precommitments_data,
                                                               len(precommitments_data), CommitmentPointer(commitment))

        if code != MusigRes.OK:
            raise SchnorrMusigError(code)

        return bytes(commitment.data)

    def receive_commitments(self, *commitments: bytes) -> bytes:
        commitments_data = bytes()
        for commitment in commitments:
            commitments_data += commitment

        aggregated_commitment = AggregatedCommitment()
        code = self.musig.schnorr_musig_receive_commitments(self.signer, commitments_data, len(commitments_data),
                                                            AggregatedCommitmentPointer(aggregated_commitment))

        if code != MusigRes.OK:
            raise SchnorrMusigError(code)

        return bytes(aggregated_commitment.data)

    def aggregate_signature(self, *signatures: bytes) -> bytes:
        signatures_data = bytes()
        for signature in signatures:
            signatures_data += signature

        aggregated_signature = AggregatedSignature()
        code = self.musig.schnorr_musig_receive_signature_shares(self.signer, signatures_data, len(signatures_data),
                                                                 AggregatedSignaturePointer(aggregated_signature))

        if code != MusigRes.OK:
            raise SchnorrMusigError(code)

        return bytes(aggregated_signature.data)

    def verify(self, message: bytes, signature: bytes) -> bool:
        code = self.musig.schnorr_musig_verify(message, len(message), self.public_keys, len(self.public_keys),
                                               signature, len(signature))

        if code == MusigRes.OK:
            return True
        elif code == MusigRes.SIGNATURE_VERIFICATION_FAILED:
            return False
        else:
            raise SchnorrMusigError(code)

    def revoke(self):
        self.musig.schnorr_musig_delete_signer(self.signer)
