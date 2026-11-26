import sys
import unittest

sys.path.insert(0, "python")

from decryption_engine_solver import DecryptionEngineSolver


class EncodingTests(unittest.TestCase):
    def test_base64(self):
        text, trail = DecryptionEngineSolver.unwrap_encodings("SGVsbG8gd29ybGQ=")
        self.assertEqual(text, "Hello world")
        self.assertEqual(trail, ["Base64"])

    def test_hex(self):
        text, trail = DecryptionEngineSolver.unwrap_encodings("48656c6c6f")
        self.assertEqual(text, "Hello")
        self.assertEqual(trail, ["Hex"])

    def test_binary(self):
        text, trail = DecryptionEngineSolver.unwrap_encodings("01001000 01101001")
        self.assertEqual(text, "Hi")
        self.assertEqual(trail, ["Binary8"])

    def test_url(self):
        text, trail = DecryptionEngineSolver.unwrap_encodings("Hello%20World")
        self.assertEqual(text, "Hello World")
        self.assertEqual(trail, ["URL"])

    def test_morse(self):
        text, trail = DecryptionEngineSolver.unwrap_encodings("-- --- .-. ... .")
        self.assertEqual(text, "MORSE")
        self.assertIn("Morse", trail[0])


class CipherTests(unittest.TestCase):
    def test_caesar_round_trip(self):
        encrypted = DecryptionEngineSolver.caesar("Hello, world!", 3, decrypt=False)
        self.assertEqual(DecryptionEngineSolver.caesar(encrypted, 3, decrypt=True), "Hello, world!")

    def test_atbash(self):
        self.assertEqual(DecryptionEngineSolver.atbash("Hello"), "Svool")

    def test_vigenere_round_trip(self):
        encrypted = DecryptionEngineSolver.vigenere("Attack at dawn", "LEMON", decrypt=False)
        decrypted = DecryptionEngineSolver.vigenere(encrypted, "LEMON", decrypt=True)
        self.assertEqual(decrypted, "Attack at dawn")

    def test_rail_fence_round_trip(self):
        plain = "WEAREDISCOVEREDFLEEATONCE"
        pattern = []
        row, step = 0, 1
        for _ in plain:
            pattern.append(row)
            if row == 0:
                step = 1
            elif row == 2:
                step = -1
            row += step
        encrypted = "".join(ch for r in range(3)
                            for ch, prow in zip(plain, pattern) if prow == r)
        self.assertEqual(DecryptionEngineSolver.rail_fence_decrypt(encrypted, 3), plain)


class ValidationTests(unittest.TestCase):
    def test_negative_top_k_rejected(self):
        with self.assertRaises(ValueError):
            DecryptionEngineSolver.solve("Hello", top_k=0)

    def test_negative_depth_rejected(self):
        with self.assertRaises(ValueError):
            DecryptionEngineSolver.unwrap_encodings("test", max_depth=-1)

    def test_no_false_ascii_ioc(self):
        self.assertEqual(DecryptionEngineSolver.index_of_coincidence("12345"), 0.0)


if __name__ == "__main__":
    unittest.main()
