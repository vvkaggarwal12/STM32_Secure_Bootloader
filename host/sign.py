from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import hashlib

def generate_key_pair():
    """
    Generates an RSA key pair.

    Returns:
        private_key: The generated RSA private key.
        public_key: The generated RSA public key.
    """
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    except Exception as e:
        raise RuntimeError(f"Failed to generate key pair: {e}")

def serialize_key(key, is_private=False):
    """
    Serializes the given key to PEM format.

    Args:
        key: The key to serialize.
        is_private: Boolean indicating if the key is private.

    Returns:
        pem: The PEM formatted key.
    """
    try:
        if is_private:
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        return pem
    except Exception as e:
        raise RuntimeError(f"Failed to serialize key: {e}")

def calculate_sha256_hash(message):
    """
    Calculates the SHA-256 hash of the given message.

    Args:
        message: The message to hash.

    Returns:
        digest: The SHA-256 hash of the message.
    """
    try:
        hash_object = hashlib.sha256()
        hash_object.update(message)
        digest = hash_object.digest()
        return digest
    except Exception as e:
        raise RuntimeError(f"Failed to calculate SHA-256 hash: {e}")

def sign_hash(private_key, digest):
    """
    Signs the given hash using the private key.

    Args:
        private_key: The RSA private key.
        digest: The hash to sign.

    Returns:
        signature: The signature of the hash.
    """
    try:
        # Sign the digest using PKCS#1 v1.5 padding
        signature = private_key.sign(
            digest,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256())
        )
        return signature
    except Exception as e:
        raise RuntimeError(f"Failed to sign hash: {e}")

def verify_signature(public_key, signature, digest):
    """
    Verifies the given signature using the public key.

    Args:
        public_key: The RSA public key.
        signature: The signature to verify.
        digest: The original hash to verify against.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

def print_in_c_array(byte_string):
    # Convert to C array format
    c_array = ', '.join(f'0x{byte:02x}' for byte in byte_string)
    c_array = f'unsigned char digest[] = {{ {c_array} }};'

    print(c_array)

def main():
    try:
        # Generate RSA key pair
        private_key, public_key = generate_key_pair()

        # Serialize keys to PEM format
        # private_pem = serialize_key(private_key, is_private=True)
        # public_pem = serialize_key(public_key, is_private=False)
        private_pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAoTqUl+wfC9RR3T8dGCVjhZ9b0+oKpg4aagYcTtKmNOjX/595\nnXfWZjLIb4aIUeYzB2YWgVdu0OAwpW/o1Gw7WRl3DyKLvALXrNZKEgqc9PwmO3HE\n7pN0Gcnr5kfHsfNmZ/vkt4lkcxnqXl548xS0ZPp4brlTQ6sKfMf3Kb/xvLiLZind\nYjDQuV1s3792Z9s2v6Qli6SPfBYcQ262NZL1FcTy/FrF12CKB84l8Qmx2RxELHdT\npQ0V1Fx4ZvamJtVr7KCPgd/ULJLlaSoequn+P1M8GQi4Cqggy48BhiJ30MTS6ZNa\nlmjkT55zHH1pIOlIPeP9pjPvduyrv5jQdTYDwwIDAQABAoIBACS5gz9XuXqoUj1j\nMu1dFt5I/lG27dYFQF8GJUyPDuzeXNUNLlaABYYh6yX8LvD4zobQ6i9sCwHpDyuf\n4hkAzkPtWQFJjSq2OwpThWu2nynuhYbk00bEr51wMRuzHfmax6jH58Emuoq9THVS\nb5pvDOgzZVtTO3QecbUal2IbJqUlxypklyZAheH7Wk2RK+wYRBV0XKjlTL2BwbWU\nk4wPTjf+RplTCP/7DChVVkpvE4qPC2iXJEhJygltaQbVbQMiriyIGoG02CM1WndL\n2qcFTCy6ZT/qgxfkMpx/0suBcWgeSq36FszOWYsDiblpZCu3Y0IVpjO/OYuTw39k\n2HVWGQECgYEA3pWcdU+wlo2JmkDk+q1F6JiePwgEBe+hL+72DtpvApGwRCiXnWn4\n8vHQ4aFFjmLKTuDrCSmu6v2YXgScVr7rObcpMyOBuG4uWNFXA1JYYuPnhv81NeC5\n0HNGYBmVM9mPMv4ANSQbyQP7YKCPYcFOSYup6Ho9jfipDV2K6H4PfYkCgYEAuW7x\nzfUCoDLwsl1adTDFUcIt7Jj+1CIFiW0O3AbbDzN422vhTN5hnrXt7MmAIEdbL1Vh\n0KpSDfk17iK46BdAVIU0Sl2OOyjljKaIcOeGBye5UvgUwppNnohCVPN51lKVnGrO\nmwnyc3yHAPnRiMuDsJvZW4b2+d2FfJRl2T+cz+sCgYEArT/gh0Me3SCP4Vvvntqt\n1mysh70yfHhXixrBtS/6RhKmE3dRA7qPhnIINwczP6/PbnQNHZWvS8NWDKAkHDUA\nnGzfialyd95y/rj6tGAs4dQoy1/rx+MCXqjLN1PSWYhWuMcR3EsdwWnzCPQQhnNS\n/1XRS12SeeX5l6iezXYJkpkCgYBpx2EGlPKHgieOB/TXDxgweG2MHwaW6kVwTJcC\naqLBvCIAQT0HhX/4cl2kCpodT7czfChNSSt/rx7VllcWhlT7IfVfSpkdJEo1/rWs\nelYZdM6iBsSI8k6+1YnJPg7NdNTFoqPzCyyUNoAozVl7CGU59N17+bSfen9wPpMO\n59vDOwKBgFrNglGipu1hKdgO1dt/I1e2ucKggIBIA7uprrWsWyrPmvLg8LaOBjWs\npTBnAKF+coW3uN5wlkVfieLueuavJ+fKzMXQwgAUywEXzl2JCjOomIipzijsMrHv\nmEJ25lJw/EVKycbZL3XOmOKKZVWMAIWURxoFy885HdmmmGcoEfNn\n-----END RSA PRIVATE KEY-----\n'
        public_pem = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoTqUl+wfC9RR3T8dGCVj\nhZ9b0+oKpg4aagYcTtKmNOjX/595nXfWZjLIb4aIUeYzB2YWgVdu0OAwpW/o1Gw7\nWRl3DyKLvALXrNZKEgqc9PwmO3HE7pN0Gcnr5kfHsfNmZ/vkt4lkcxnqXl548xS0\nZPp4brlTQ6sKfMf3Kb/xvLiLZindYjDQuV1s3792Z9s2v6Qli6SPfBYcQ262NZL1\nFcTy/FrF12CKB84l8Qmx2RxELHdTpQ0V1Fx4ZvamJtVr7KCPgd/ULJLlaSoequn+\nP1M8GQi4Cqggy48BhiJ30MTS6ZNalmjkT55zHH1pIOlIPeP9pjPvduyrv5jQdTYD\nwwIDAQAB\n-----END PUBLIC KEY-----\n'
        private_key = load_pem_private_key(private_pem.encode(), password=None)

        # Print keys
        print("Private Key: ", private_pem)
        print("")
        print("Public Key: ", public_pem)
        print("")

        # Message to be hashed and signed
        message = bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60,
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
            0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80,
            0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
            0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0,
            0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
            0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
            0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0,
            0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
            0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0,
            0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x00,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60,
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
            0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80,
            0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
            0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0,
            0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
            0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
            0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0,
            0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
            0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0,
            0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x00
        ])

        # Calculate SHA-256 hash
        digest = calculate_sha256_hash(message)

        print("Hash: ", digest)
        print_in_c_array(digest)
        print("")

        # Sign the hash using the private key
        signature = sign_hash(private_key, digest)

        # Print the signature
        print("Signature: ", signature)
        print_in_c_array(signature)
        print("")

        # Verify the signature using the public key
        is_valid = verify_signature(public_key, signature, digest)

        if is_valid:
            print("Signature is valid.")
        else:
            print("Signature is not valid.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()