
import os

from .feistel import FeistelFPE


def main():
    key = os.urandom(32)

    cipher = FeistelFPE(
        key=key,
        alphabet="0123456789",
        rounds=12
    )

    test_values = [
        "79161234567",          # 11 цифр
        "123456789",            # 9 цифр
        "1234567890123",        # 13 цифр
        "1234567890123456",     # 16 цифр
        "12345678901234567890"  # 20 цифр
    ]

    for original in test_values:
        encrypted = cipher.encrypt(original)
        decrypted = cipher.decrypt(encrypted)

        print("-" * 45)
        print("Исходное значение:", original)
        print("Зашифрованное:", encrypted)
        print("Расшифрованное:", decrypted)
        print("Длина:", len(encrypted))

        assert len(encrypted) == len(original)
        assert decrypted == original

    print("\nВсе проверки пройдены!")


if __name__ == "__main__":
    main()
