import abc
import ctypes.util
from ctypes import Structure
from ctypes import c_size_t
from ctypes import c_ubyte
from ctypes import c_uint32
from enum import IntEnum

LIBRARY_NAME = 'musig_c'
STANDARD_ENCODING_LENGTH = 32
AGG_SIG_ENCODING_LENGTH = 64


class MusigRes(IntEnum):
    OK = 0,
    INVALID_INPUT_DATA = 1,
    ENCODING_ERROR = 2,
    SIGNATURE_VERIFICATION_FAILED = 3,
    INTERNAL_ERROR = 4,
    INVALID_PUBKEY_LENGTH = 100,
    NONCE_COMMITMENT_NOT_GENERATED = 101,
    NONCE_PRECOMMITMENTS_NOT_RECEIVED = 102,
    NONCE_PRECOMMITMENTS_AND_PARTICIPANTS_NOT_MATCH = 103,
    NONCE_COMMITMENTS_NOT_RECEIVED = 104,
    NONCE_COMMITMENTS_AND_PARTICIPANTS_NOT_MATCH = 105,
    SIGNATURE_SHARE_AND_PARTICIPANTS_NOT_MATCH = 106,
    COMMITMENT_IS_NOT_IN_CORRECT_SUBGROUP = 106,
    INVALID_COMMITMENT = 107,
    INVALID_PUBLIC_KEY = 108,
    INVALID_PARTICIPANT_POSITION = 109,
    AGGREGATED_NONCE_COMMITMENT_NOT_COMPUTED = 110,
    CHALLENGE_NOT_GENERATED = 111,
    INVALID_SIGNATURE_SHARE = 112,
    INVALID_SEED = 113


class AggregatedPublicKey(Structure):
    _fields_ = [
        ("data", c_ubyte * STANDARD_ENCODING_LENGTH),
    ]


AggregatedPublicKeyPointer = ctypes.POINTER(AggregatedPublicKey)


class MusigBN256Signer(Structure):
    pass


MusigBN256SignerPointer = ctypes.POINTER(MusigBN256Signer)


class MusigSigner(Structure):
    _fields_ = [
        ("inner", MusigBN256SignerPointer),
    ]


MusigSignerPointer = ctypes.POINTER(MusigSigner)


class Precommitment(Structure):
    _fields_ = [
        ("data", c_ubyte * STANDARD_ENCODING_LENGTH),
    ]


PrecommitmentPointer = ctypes.POINTER(Precommitment)


class AggregatedCommitment(Structure):
    _fields_ = [
        ("data", c_ubyte * STANDARD_ENCODING_LENGTH),
    ]


AggregatedCommitmentPointer = ctypes.POINTER(AggregatedCommitment)


class Commitment(Structure):
    _fields_ = [
        ("data", c_ubyte * STANDARD_ENCODING_LENGTH),
    ]


CommitmentPointer = ctypes.POINTER(Commitment)


class Signature(Structure):
    _fields_ = [
        ("data", c_ubyte * STANDARD_ENCODING_LENGTH),
    ]


SignaturePointer = ctypes.POINTER(Signature)


class AggregatedSignature(Structure):
    _fields_ = [
        ("data", c_ubyte * AGG_SIG_ENCODING_LENGTH),
    ]


AggregatedSignaturePointer = ctypes.POINTER(AggregatedSignature)


class SchnorrMusigNative(ctypes.CDLL):

    @abc.abstractmethod
    def schnorr_musig_new_signer(self, encoded_pubkeys: c_ubyte * STANDARD_ENCODING_LENGTH,
                                 encoded_pubkeys_len: c_size_t, position: c_size_t) -> MusigSignerPointer:
        pass

    @abc.abstractmethod
    def schnorr_musig_delete_signer(self, signer: MusigSignerPointer) -> None:
        pass

    @abc.abstractmethod
    def schnorr_musig_aggregate_pubkeys(slf, encoded_pubkeys: c_ubyte * STANDARD_ENCODING_LENGTH,
                                        encoded_pubkeys_len: c_size_t,
                                        aggregate_pubkeys: AggregatedPublicKeyPointer) -> MusigRes:
        pass

    @abc.abstractmethod
    def schnorr_musig_compute_precommitment(self, signer: MusigSignerPointer, seed: c_uint32 * STANDARD_ENCODING_LENGTH,
                                            seed_len: c_size_t, precommitment: PrecommitmentPointer) -> MusigRes:
        pass

    @abc.abstractmethod
    def schnorr_musig_receive_precommitments(self, signer: MusigSignerPointer,
                                             input: c_ubyte * STANDARD_ENCODING_LENGTH,
                                             input_len: c_size_t,
                                             commitment: CommitmentPointer) -> MusigRes:
        pass

    @abc.abstractmethod
    def schnorr_musig_receive_commitments(self, signer: MusigSignerPointer,
                                          input: c_ubyte * STANDARD_ENCODING_LENGTH,
                                          input_len: c_size_t,
                                          commitment: AggregatedCommitmentPointer) -> MusigRes:
        pass

    @abc.abstractmethod
    def schnorr_musig_receive_signature_shares(self, signer: MusigSignerPointer,
                                               input: c_ubyte * STANDARD_ENCODING_LENGTH,
                                               input_len: c_size_t,
                                               signature_shares: AggregatedSignaturePointer) -> MusigRes:
        pass

    @abc.abstractmethod
    def schnorr_musig_sign(self, signer: MusigSignerPointer, private_key: c_ubyte * STANDARD_ENCODING_LENGTH,
                           private_key_len: c_size_t, message: c_ubyte * STANDARD_ENCODING_LENGTH,
                           message_len: c_size_t, signature: SignaturePointer) -> MusigRes:
        pass

    @abc.abstractmethod
    def schnorr_musig_verify(self, message: c_ubyte * STANDARD_ENCODING_LENGTH, message_len: c_size_t,
                             encoded_pubkeys: c_ubyte * STANDARD_ENCODING_LENGTH, encoded_pubkeys_len: c_size_t,
                             encoded_signature: c_ubyte * STANDARD_ENCODING_LENGTH,
                             encoded_signature_len: c_size_t) -> MusigRes:
        pass


class SchnorrMusigLoader:

    @staticmethod
    def load() -> SchnorrMusigNative:
        libPath = ctypes.util.find_library(LIBRARY_NAME)
        if libPath == None:
            libPath = "./libmusig_c.so"
        library: SchnorrMusigNative = ctypes.CDLL(libPath)
        library.schnorr_musig_new_signer.restype = MusigSignerPointer
        library.schnorr_musig_aggregate_pubkeys.restype = MusigRes
        library.schnorr_musig_compute_precommitment.restype = MusigRes
        library.schnorr_musig_receive_precommitments.restype = MusigRes
        library.schnorr_musig_receive_commitments.restype = MusigRes
        library.schnorr_musig_receive_signature_shares.restype = MusigRes
        library.schnorr_musig_sign.restype = MusigRes
        library.schnorr_musig_verify.restype = MusigRes
        return library
