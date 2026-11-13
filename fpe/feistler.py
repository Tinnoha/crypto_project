
import hashlib
import hmac


class FeistelFPE:
    """
    Учебная реализация форматосохраняющего преобразования
    на основе сбалансированной сети Фейстеля.

    Ограничения:
    - длина строки должна быть чётной;
    - используется фиксированный алфавит;
    - алгоритм не является NIST FF1/FF3-1.
    """

    def __init__(
        self,
        key: bytes,
        alphabet: str = "0123456789",
        rounds: int = 10
    ):
        if len(key) < 32:
            raise ValueError("Ключ должен содержать минимум 32 байта")

        if len(set(alphabet)) != len(alphabet):
            raise ValueError("Символы алфавита должны быть уникальными")

        if len(alphabet) < 2:
            raise ValueError("Алфавит должен содержать минимум 2 символа")

        if rounds < 8:
            raise ValueError("Необходимо минимум 8 раундов")

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
            result = (
                result * self.base
                + self.char_to_int[char]
            )

        return result

    def _round_function(
        self,
        right: int,
        round_number: int,
        half_length: int
    ) -> int:
        """
        HMAC-SHA256 используется как раундовая функция.
        """
        right_bytes = right.to_bytes(
            max(1, (half_length * self.base.bit_length() + 7) // 8),
            "big"
        )

        message = (
            round_number.to_bytes(4, "big")
            + right_bytes
        )

        digest = hmac.new(
            self.key,
            message,
            hashlib.sha256
        ).digest()

        return int.from_bytes(digest, "big") % (
            self.base ** half_length
        )

    def encrypt(self, plaintext: str) -> str:
        return self._transform(plaintext, decrypt=False)

    def decrypt(self, ciphertext: str) -> str:
        return self._transform(ciphertext, decrypt=True)

    def _transform(self, value: str, decrypt: bool) -> str:
        if not value or len(value) % 2 != 0:
            raise ValueError(
                "Строка должна иметь ненулевую чётную длину"
            )

        if any(char not in self.char_to_int for char in value):
            raise ValueError("Недопустимые символы")

        half_length = len(value) // 2
        modulus = self.base ** half_length

        left = self._decode_number(value[:half_length])
        right = self._decode_number(value[half_length:])

        rounds = range(
            self.rounds - 1, -1, -1
        ) if decrypt else range(self.rounds)

        for round_number in rounds:
            if decrypt:
                left, right = (
                    (right - self._round_function(
                        left, round_number, half_length
                    )) % modulus,
                    left
                )
            else:
                left, right = (
                    right,
                    (left + self._round_function(
                        right, round_number, half_length
                    )) % modulus
                )

        return (
            self._encode_number(left, half_length)
            + self._encode_number(right, half_length)
        )
