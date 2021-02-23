from ctypes import c_size_t
from ctypes import c_ubyte
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

    def create_signer_from_keys(self, public_keys: List[List[int]], position: int) -> SchnorrMusigSigner:
        encoded_public_keys = []
        for public_key in public_keys:
            encoded_public_keys += public_key
        encoded_public_keys_len = len(encoded_public_keys)
        signer = self.musig.schnorr_musig_new_signer((c_ubyte * encoded_public_keys_len)(*encoded_public_keys),
                                                     c_size_t(encoded_public_keys_len), c_size_t(position))

        return SchnorrMusigSigner(self.musig, signer, public_keys[position])

    def create_signer_from_encoded_keys(self, encoded_public_keys: List[int], position: int) -> SchnorrMusigSigner:
        public_keys_len = len(encoded_public_keys)
        signer = self.musig.schnorr_musig_new_signer((c_ubyte * public_keys_len)(*encoded_public_keys),
                                                     c_size_t(public_keys_len), c_size_t(position))
        start_index = position * STANDARD_ENCODING_LENGTH
        public_key = encoded_public_keys[start_index: start_index + STANDARD_ENCODING_LENGTH]

        return SchnorrMusigSigner(self.musig, signer, public_key)

    def create_signer_from_key(self, public_key: List[int]) -> SchnorrMusigSigner:
        public_key_len = len(public_key)
        signer = self.musig.schnorr_musig_new_signer((c_ubyte * public_key_len)(*public_key),
                                                     c_size_t(public_key_len), c_size_t(0))

        return SchnorrMusigSigner(self.musig, signer, public_key)

    def verify_by_public_keys(self, message: List[int], signature: AggregatedSignature, public_keys: List[int]) -> bool:
        message_len = len(message)
        public_keys_len = len(public_keys)

        code = self.musig.schnorr_musig_verify((c_ubyte * message_len)(*message), c_size_t(message_len),
                                               (c_ubyte * public_keys_len)(*public_keys), c_size_t(public_keys_len),
                                               signature.data, c_size_t(len(signature.data)))

        if code == MusigRes.OK:
            return True
        elif code == MusigRes.SIGNATURE_VERIFICATION_FAILED:
            return False
        else:
            raise SchnorrMusigError(code)

    def verify_by_agg_public_keys(self, message: List[int], signature: AggregatedSignature, aggregated_public_keys: AggregatedPublicKey) -> bool:
        message_len = len(message)
        code = self.musig.schnorr_musig_verify((c_ubyte * message_len)(*message), c_size_t(message_len),
                                               aggregated_public_keys.data, c_size_t(len(aggregated_public_keys.data)),
                                               signature.data, c_size_t(len(signature.data)))

        if code == MusigRes.OK:
            return True
        elif code == MusigRes.SIGNATURE_VERIFICATION_FAILED:
            return False
        else:
            raise SchnorrMusigError(code)
        pass

    def aggregate_public_keys(self, public_keys: List[int]) -> AggregatedPublicKey:
        public_keys_len = len(public_keys)

        aggregated_public_key = AggregatedPublicKey()
        code = self.musig.schnorr_musig_aggregate_pubkeys((c_ubyte * public_keys_len)(*public_keys),
                                                          c_size_t(public_keys_len),
                                                          AggregatedPublicKeyPointer(aggregated_public_key))

        if code != MusigRes.OK:
            raise SchnorrMusigError(code)

        return aggregated_public_key
