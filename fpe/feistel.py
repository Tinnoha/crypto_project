
import hashlib
import hmac


class FeistelFPE:
    """
    Учебная реализация форматосохраняющего преобразования
    на основе обобщённой сети Фейстеля.

    Поддерживает чётную и нечётную длину входной строки.
    """

    def __init__(
        self,
        key: bytes,
        alphabet: str = "0123456789",
        rounds: int = 12
    ):
        if len(key) < 32:
            raise ValueError("Ключ должен содержать минимум 32 байта")

        if len(set(alphabet)) != len(alphabet):
            raise ValueError("Символы алфавита должны быть уникальными")

        if len(alphabet) < 2:
            raise ValueError("Алфавит должен содержать минимум 2 символа")

        if rounds < 8 or rounds % 2 != 0:
            raise ValueError(
                "Количество раундов должно быть чётным и не меньше 8"
            )

        self.key = key
        self.alphabet = alphabet
        self.base = len(alphabet)
        self.rounds = rounds

        self.char_to_int = {
            char: i for i, char in enumerate(alphabet)
        }

    def _encode_number(self, value: int, length: int) -> str:
        result = []

        for _ in range(length):
            result.append(self.alphabet[value % self.base])
            value //= self.base

        if value:
            raise ValueError("Число не помещается в заданную длину")

        return "".join(reversed(result))

    def _decode_number(self, value: str) -> int:
        result = 0

        for char in value:
            result = result * self.base + self.char_to_int[char]

        return result

    def _round_function(
        self,
        right: int,
        round_number: int,
        right_length: int,
        output_length: int
    ) -> int:

        byte_length = max(
            1,
            (right_length * self.base.bit_length() + 7) // 8
        )

        right_bytes = right.to_bytes(byte_length, "big")

        message = (
            b"GENERAL-FEISTEL-V1"
            + round_number.to_bytes(4, "big")
            + right_length.to_bytes(4, "big")
            + output_length.to_bytes(4, "big")
            + right_bytes
        )

        digest = hmac.new(
            self.key,
            message,
            hashlib.sha256
        ).digest()

        return int.from_bytes(digest, "big") % (
            self.base ** output_length
        )

    def encrypt(self, plaintext: str) -> str:
        return self._transform(plaintext, decrypt=False)

    def decrypt(self, ciphertext: str) -> str:
        return self._transform(ciphertext, decrypt=True)

    def _transform(self, value: str, decrypt: bool) -> str:

        if not value:
            raise ValueError("Строка не должна быть пустой")

        if any(char not in self.char_to_int for char in value):
            raise ValueError("Обнаружены недопустимые символы")

        # Разделяем строку на две части.
        left_length = len(value) // 2
        right_length = len(value) - left_length

        left = self._decode_number(value[:left_length])
        right = self._decode_number(value[left_length:])

        if decrypt:
            round_sequence = range(self.rounds - 1, -1, -1)
        else:
            round_sequence = range(self.rounds)

        for round_number in round_sequence:

            if decrypt:
                # Обратный раунд Фейстеля.
                old_left = (
                    right - self._round_function(
                        left,
                        round_number,
                        left_length,
                        right_length
                    )
                ) % (self.base ** right_length)

                old_right = left

                left, right = old_left, old_right
                left_length, right_length = (
                    right_length,
                    left_length
                )

            else:
                # Прямой раунд Фейстеля.
                new_left = right

                new_right = (
                    left + self._round_function(
                        right,
                        round_number,
                        right_length,
                        left_length
                    )
                ) % (self.base ** left_length)

                left, right = new_left, new_right
                left_length, right_length = (
                    right_length,
                    left_length
                )

        return (
            self._encode_number(left, left_length)
            + self._encode_number(right, right_length)
        )
