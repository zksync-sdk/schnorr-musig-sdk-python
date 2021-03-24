from zksync.sdk.musig.schnorr_musig_native import MusigRes


class SchnorrMusigError(Exception):

    def __init__(self, code: MusigRes) -> None:
        self.code = code
