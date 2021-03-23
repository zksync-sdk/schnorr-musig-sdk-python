from typing import List

from _functools import reduce

from zksync.sdk.musig.schnorr_musig_error import SchnorrMusigError
from zksync.sdk.musig.schnorr_musig_native import SchnorrMusigLoader
from zksync.sdk.musig.schnorr_musig_signer import AggregatedPublicKey
from zksync.sdk.musig.schnorr_musig_signer import AggregatedPublicKeyPointer
from zksync.sdk.musig.schnorr_musig_signer import MusigRes
from zksync.sdk.musig.schnorr_musig_signer import SchnorrMusigSigner


class SchnorrMusig:

    def __init__(self) -> None:
        self.musig = SchnorrMusigLoader.load()

    def create_signer(self, public_keys: List[bytes], position: int = 0) -> SchnorrMusigSigner:
        encoded_public_keys = reduce(lambda x, y: x + y, public_keys)
        signer = self.musig.schnorr_musig_new_signer(encoded_public_keys, len(encoded_public_keys), position)
        return SchnorrMusigSigner(self.musig, signer, encoded_public_keys)

    def verify(self, message: bytes, signature: bytes, *public_keys: bytes) -> bool:
        encoded_public_keys = reduce(lambda x, y: x + y, public_keys)
        code = self.musig.schnorr_musig_verify(message, len(message), encoded_public_keys, len(encoded_public_keys),
                                               signature, len(signature))

        if code == MusigRes.OK:
            return True
        elif code == MusigRes.SIGNATURE_VERIFICATION_FAILED:
            return False
        else:
            raise SchnorrMusigError(code)

    def aggregate_public_keys(self, public_keys: List[bytes]) -> bytes:
        encoded_public_keys = reduce(lambda x, y: x + y, public_keys)
        aggregated_public_key = AggregatedPublicKey()
        code = self.musig.schnorr_musig_aggregate_pubkeys(encoded_public_keys, len(encoded_public_keys),
                                                          AggregatedPublicKeyPointer(aggregated_public_key))

        if code != MusigRes.OK:
            raise SchnorrMusigError(code)

        return bytes(aggregated_public_key.data)
