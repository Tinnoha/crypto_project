
import os

from vault import TokenVault


def main():
    # В реальном окружении ключ должен поступать
    # из защищённого хранилища ключей.
    master_key = os.urandom(32)

    vault = TokenVault(
        database="token_vault.db",
        master_key=master_key
    )

    original_value = "1234567890123456"

    # Токенизация с использованием AES-GCM.
    token_gcm = vault.tokenize(
        original_value,
        mode="AES-GCM"
    )

    # Повторное получение токена.
    same_token = vault.tokenize(
        original_value,
        mode="AES-GCM"
    )

    # Восстановление оригинального значения.
    restored = vault.detokenize(token_gcm)

    print("Оригинал:", original_value)
    print("Токен:", token_gcm)
    print("Повторный токен:", same_token)
    print("Восстановленное значение:", restored)

    assert token_gcm == same_token
    assert restored == original_value

    # Проверка второго режима.
    token_siv = vault.tokenize(
        "9876543210987654",
        mode="AES-SIV"
    )

    restored_siv = vault.detokenize(token_siv)

    print("\nAES-SIV:")
    print("Токен:", token_siv)
    print("Восстановленное значение:", restored_siv)

    assert restored_siv == "9876543210987654"

    print("\nВсе проверки пройдены!")


if __name__ == "__main__":
    main()
