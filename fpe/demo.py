
import os

from feistel import FeistelFPE


def main():
    key = os.urandom(32)

    cipher = FeistelFPE(
        key=key,
        alphabet="0123456789",
        rounds=12
    )

    original = "123456789012"

    encrypted = cipher.encrypt(original)
    decrypted = cipher.decrypt(encrypted)

    print("Исходные данные:", original)
    print("Зашифрованные данные:", encrypted)
    print("Расшифрованные данные:", decrypted)

    assert len(original) == len(encrypted)
    assert original == decrypted

    print("Проверка пройдена!")


if __name__ == "__main__":
    main()
