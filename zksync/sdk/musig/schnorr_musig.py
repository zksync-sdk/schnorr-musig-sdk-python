from zksync.sdk.musig.schnorr_musig_error import SchnorrMusigError
from zksync.sdk.musig.schnorr_musig_native import SchnorrMusigLoader
from zksync.sdk.musig.schnorr_musig_signer import AggregatedPublicKey
from zksync.sdk.musig.schnorr_musig_signer import AggregatedPublicKeyPointer
from zksync.sdk.musig.schnorr_musig_signer import MusigRes
from zksync.sdk.musig.schnorr_musig_signer import SchnorrMusigSigner


class SchnorrMusig:

    def __init__(self) -> None:
        self.musig = SchnorrMusigLoader.load()

    def create_signer(self, public_keys: bytes, position: int = 0) -> SchnorrMusigSigner:
        signer = self.musig.schnorr_musig_new_signer(public_keys, len(public_keys), position)
        return SchnorrMusigSigner(self.musig, signer, public_keys)

    def verify(self, message: bytes, signature: bytes, public_keys: bytes) -> bool:

        code = self.musig.schnorr_musig_verify(message, len(message), public_keys, len(public_keys), signature,
                                               len(signature))

        if code == MusigRes.OK:
            return True
        elif code == MusigRes.SIGNATURE_VERIFICATION_FAILED:
            return False
        else:
            raise SchnorrMusigError(code)

    def aggregate_public_keys(self, public_keys: bytes) -> bytes:

        aggregated_public_key = AggregatedPublicKey()
        code = self.musig.schnorr_musig_aggregate_pubkeys(public_keys, len(public_keys),
                                                          AggregatedPublicKeyPointer(aggregated_public_key))

        if code != MusigRes.OK:
            raise SchnorrMusigError(code)

        return bytes(aggregated_public_key.data)
