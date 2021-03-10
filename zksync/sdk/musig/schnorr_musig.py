from typing import List

from zksync.sdk.musig.schnorr_musig_error import SchnorrMusigError
from zksync.sdk.musig.schnorr_musig_native import STANDARD_ENCODING_LENGTH
from zksync.sdk.musig.schnorr_musig_native import SchnorrMusigLoader
from zksync.sdk.musig.schnorr_musig_signer import AggregatedPublicKey
from zksync.sdk.musig.schnorr_musig_signer import AggregatedPublicKeyPointer
from zksync.sdk.musig.schnorr_musig_signer import AggregatedSignature
from zksync.sdk.musig.schnorr_musig_signer import MusigRes
from zksync.sdk.musig.schnorr_musig_signer import SchnorrMusigSigner


class SchnorrMusig:

    def __init__(self) -> None:
        self.musig = SchnorrMusigLoader.load()

    def create_signer_from_keys(self, public_keys: List[bytes], position: int) -> SchnorrMusigSigner:
        encoded_public_keys = bytes()
        for public_key in public_keys:
            encoded_public_keys += public_key

        signer = self.musig.schnorr_musig_new_signer(encoded_public_keys, len(encoded_public_keys), position)
        return SchnorrMusigSigner(self.musig, signer, public_keys[position])

    def create_signer_from_encoded_keys(self, encoded_public_keys: bytes, position: int) -> SchnorrMusigSigner:
        signer = self.musig.schnorr_musig_new_signer(encoded_public_keys, len(encoded_public_keys), position)
        start_index = position * STANDARD_ENCODING_LENGTH
        public_key = encoded_public_keys[start_index: start_index + STANDARD_ENCODING_LENGTH]
        return SchnorrMusigSigner(self.musig, signer, public_key)

    def create_signer_from_key(self, public_key: bytes) -> SchnorrMusigSigner:
        signer = self.musig.schnorr_musig_new_signer(public_key, len(public_key), 0)
        return SchnorrMusigSigner(self.musig, signer, public_key)

    def verify_by_public_keys(self, message: bytes, signature: AggregatedSignature, public_keys: bytes) -> bool:

        code = self.musig.schnorr_musig_verify(message, len(message), public_keys, len(public_keys), signature.data,
                                               len(signature.data))

        if code == MusigRes.OK:
            return True
        elif code == MusigRes.SIGNATURE_VERIFICATION_FAILED:
            return False
        else:
            raise SchnorrMusigError(code)

    def verify_by_agg_public_key(self, message: bytes, signature: AggregatedSignature,
                                 aggregated_public_keys: AggregatedPublicKey) -> bool:
        code = self.musig.schnorr_musig_verify(message, len(message), aggregated_public_keys.data,
                                               len(aggregated_public_keys.data), signature.data, len(signature.data))

        if code == MusigRes.OK:
            return True
        elif code == MusigRes.SIGNATURE_VERIFICATION_FAILED:
            return False
        else:
            raise SchnorrMusigError(code)
        pass

    def aggregate_public_keys(self, public_keys: bytes) -> AggregatedPublicKey:

        aggregated_public_key = AggregatedPublicKey()
        code = self.musig.schnorr_musig_aggregate_pubkeys(public_keys, len(public_keys),
                                                          AggregatedPublicKeyPointer(aggregated_public_key))

        if code != MusigRes.OK:
            raise SchnorrMusigError(code)

        return aggregated_public_key
