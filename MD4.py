import sys
import struct


def pad_message(message: bytes) -> bytes:
    """
    Append padding bits to the message. For the resulting padded message, its length times 8 is congruent to 448 mod 512
    """

    # Append a single '1'
    padded_message = message + b'\x80'

    # If necessary, append remaining '0's
    original_bit_length = len(padded_message) * 8
    padding_length = (448 - original_bit_length) % 512
    padded_message += b'\x00' * (padding_length // 8)

    return padded_message


def append_length(message: bytes, original_length: int) -> bytes:
    """
    Append the length of the original message as a 64-bit representation (low-order bytes first)
    """

    original_bit_length = original_length * 8

    # If length exceeds 2^64, take only the low-order 64-bits
    original_bit_length = original_bit_length & ((1 << 64) - 1)

    return message + original_bit_length.to_bytes(length=8, byteorder='little')


def left_rotate(X: int, N: int) -> int:
    """
    Circularly shift an integer X left by N positions
    :return: A 32-bit integer value
    """

    return ((X << N) | (X >> (32 - N))) & 0xFFFFFFFF


def md4(message: bytes) -> bytes:
    """
    The MD4 algorithm for producing the hash
    """

    # Message pre-processing: Total length is a multiple of 512 bits
    initial_message_byte_length = len(message)
    message = append_length(pad_message(message), initial_message_byte_length)

    # Initialize
    buffers = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    block_size_words = 16
    num_blocks = len(message) // (4 * block_size_words)

    # Process each 16-word block
    for i in range(num_blocks):

        # Copy block i into X
        block_start = i * 4 * block_size_words
        block_end = (i + 1) * 4 * block_size_words
        block = message[block_start:block_end]

        # Interpret the block as 16 unsigned integers (4 bytes each)
        X = list(struct.unpack("<16I", block))

        A, B, C, D = buffers

        # Round 1
        A, B, C, D = round_1(A, B, C, D, X)

        # Round 2
        A, B, C, D = round_2(A, B, C, D, X)

        # Round 3
        A, B, C, D = round_3(A, B, C, D, X)

        # Update hash values
        buffers = [(v + n) & 0xFFFFFFFF for v, n in zip([A, B, C, D], buffers)]

    # Convert the final hash values to bytes
    return struct.pack("<4L", *buffers)


def md4_hex_digest(message: bytes) -> str:
    """
    Converts the hash bytes to a hex string
    """

    return md4(message).hex()


def operation_round_1(A: int, B: int, C: int, D: int, X: int, S: int) -> int:
    """
    The Operation of Round 1
    """

    return left_rotate(A + ((f(B, C, D) & 0xFFFFFFFF) + X) & 0xFFFFFFFF, S)


def round_1(A: int, B: int, C: int, D: int, X: list) -> tuple:
    """
    Computations of Round 1
    """

    A = operation_round_1(A, B, C, D, X[0], 3)
    D = operation_round_1(D, A, B, C, X[1], 7)
    C = operation_round_1(C, D, A, B, X[2], 11)
    B = operation_round_1(B, C, D, A, X[3], 19)

    A = operation_round_1(A, B, C, D, X[4], 3)
    D = operation_round_1(D, A, B, C, X[5], 7)
    C = operation_round_1(C, D, A, B, X[6], 11)
    B = operation_round_1(B, C, D, A, X[7], 19)

    A = operation_round_1(A, B, C, D, X[8], 3)
    D = operation_round_1(D, A, B, C, X[9], 7)
    C = operation_round_1(C, D, A, B, X[10], 11)
    B = operation_round_1(B, C, D, A, X[11], 19)

    A = operation_round_1(A, B, C, D, X[12], 3)
    D = operation_round_1(D, A, B, C, X[13], 7)
    C = operation_round_1(C, D, A, B, X[14], 11)
    B = operation_round_1(B, C, D, A, X[15], 19)

    return A, B, C, D


def operation_round_2(A: int, B: int, C: int, D: int, X: int, S: int) -> int:
    """
    The Operation of Round 2
    """

    return left_rotate(A + ((g(B, C, D) & 0xFFFFFFFF) + X + 0x5A827999) & 0xFFFFFFFF, S)


def round_2(A: int, B: int, C: int, D: int, X: list) -> tuple:
    """
    Computations of Round 1
    """

    A = operation_round_2(A, B, C, D, X[0], 3)
    D = operation_round_2(D, A, B, C, X[4], 5)
    C = operation_round_2(C, D, A, B, X[8], 9)
    B = operation_round_2(B, C, D, A, X[12], 13)

    A = operation_round_2(A, B, C, D, X[1], 3)
    D = operation_round_2(D, A, B, C, X[5], 5)
    C = operation_round_2(C, D, A, B, X[9], 9)
    B = operation_round_2(B, C, D, A, X[13], 13)

    A = operation_round_2(A, B, C, D, X[2], 3)
    D = operation_round_2(D, A, B, C, X[6], 5)
    C = operation_round_2(C, D, A, B, X[10], 9)
    B = operation_round_2(B, C, D, A, X[14], 13)

    A = operation_round_2(A, B, C, D, X[3], 3)
    D = operation_round_2(D, A, B, C, X[7], 5)
    C = operation_round_2(C, D, A, B, X[11], 9)
    B = operation_round_2(B, C, D, A, X[15], 13)

    return A, B, C, D


def operation_round_3(A: int, B: int, C: int, D: int, X: int, S: int) -> int:
    """
    The Operation of Round 3
    """

    return left_rotate(A + ((h(B, C, D) & 0xFFFFFFFF) + X + 0x6ED9EBA1) & 0xFFFFFFFF, S)


def round_3(A: int, B: int, C: int, D: int, X: list) -> tuple:
    """
    Computations of Round 3
    """

    A = operation_round_3(A, B, C, D, X[0], 3)
    D = operation_round_3(D, A, B, C, X[8], 9)
    C = operation_round_3(C, D, A, B, X[4], 11)
    B = operation_round_3(B, C, D, A, X[12], 15)

    A = operation_round_3(A, B, C, D, X[2], 3)
    D = operation_round_3(D, A, B, C, X[10], 9)
    C = operation_round_3(C, D, A, B, X[6], 11)
    B = operation_round_3(B, C, D, A, X[14], 15)

    A = operation_round_3(A, B, C, D, X[1], 3)
    D = operation_round_3(D, A, B, C, X[9], 9)
    C = operation_round_3(C, D, A, B, X[5], 11)
    B = operation_round_3(B, C, D, A, X[13], 15)

    A = operation_round_3(A, B, C, D, X[3], 3)
    D = operation_round_3(D, A, B, C, X[11], 9)
    C = operation_round_3(C, D, A, B, X[7], 11)
    B = operation_round_3(B, C, D, A, X[15], 15)

    return A, B, C, D


def f(X: int, Y: int, Z: int) -> int:
    """
    Specified funtion of MD4
    """

    return (X & Y) | (~X & Z)


def g(X: int, Y: int, Z: int) -> int:
    """
    Specified funtion of MD4
    """

    return (X & Y) | (X & Z) | (Y & Z)


def h(X: int, Y: int, Z: int) -> int:
    """
    Specified funtion of MD4
    """

    return X ^ Y ^ Z


def main():

    if sys.byteorder == "big":

        print("\nThe system is currently configured with big-endianness. MD4 algorithm requires little-endianness.\
 Please configure your system to use little-endianness to proceed.")

    else:

        print("\nSystem endianness is compatible with MD4 algorithm. You can proceed with MD4 operations.")

        encoded_message = input("\nEnter your password: ").encode('utf-8')

        MD4_hash = md4_hex_digest(encoded_message)

        print(MD4_hash)


if __name__ == "__main__":
    main()
