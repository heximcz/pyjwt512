import jwt
import json
import base64
import unittest
from unittest.mock import patch, mock_open
from pyjwt512.VerifyJwtToken import VerifyJwtToken
from pyjwt512.Exceptions import InvalidTokenException

class TestVerifyJwtToken(unittest.TestCase):

    def setUp(self):
        self.verifier = VerifyJwtToken()
        self.audience = "yourAudience"
        self.cert_dir = "/path/to/cert/dir"
        self.public_key = "mocked-public-key-content"
        self.valid_token = self.create_mock_jwt()

    def create_mock_jwt(self):
        header = json.dumps({"alg": "ES512", "typ": "JWT", "kid": "vcjqicu87ciuqh"}).encode('utf-8')
        payload = json.dumps({"iss": "issuer", "aud": self.audience, "iat": "issued-at-time", "uid": 123}).encode('utf-8')
        header_encoded = base64.urlsafe_b64encode(header).decode().rstrip("=")
        payload_encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
        signature = base64.urlsafe_b64encode(b'signature').decode().rstrip("=")
        return f"{header_encoded}.{payload_encoded}.{signature}"

    def test_validate_valid_token(self):
        with patch("builtins.open", mock_open(read_data=self.public_key)):
            with patch("jwt.decode", return_value={"iss": "issuer", "aud": self.audience, "iat": "issued-at-time", "uid": 123}):
                is_valid = self.verifier.validate(self.valid_token, self.audience, self.cert_dir)
                self.assertTrue(is_valid)
                self.assertEqual(self.verifier.get_iss(), "issuer")
                self.assertEqual(self.verifier.get_aud(), self.audience)
                self.assertEqual(self.verifier.get_iat(), "issued-at-time")
                self.assertEqual(self.verifier.get_uid(), 123)

    def test_validate_invalid_token(self):
        invalid_token = 'invalid.jwt.token'
        with patch("builtins.open", mock_open(read_data=self.public_key)):
            with patch("jwt.decode", side_effect=jwt.InvalidTokenError):
                with self.assertRaises(InvalidTokenException):
                    self.verifier.validate(invalid_token, self.audience, self.cert_dir)

    def test_str_representation(self):
        expected_representation = f"iss : {None}, aud : {None}, iat : {None}, uid : {None}, kid : {None}"
        self.assertEqual(str(self.verifier), expected_representation)
