import unittest
from unittest.mock import Mock, patch
from pyjwt512.Exceptions import CreateTokenException
from pyjwt512.CreateJwtToken import CreateJwtToken

class TestCreateJwtToken(unittest.TestCase):


    def setUp(self):
        self.valid_payload = {'iss': 'issuer', 'aud': 'audience', 'uid': 123}
        self.cert_dir = '/path/to/cert'
    
    # def create_mock_es512_manager(self):
    #     mock_es512_manager = Mock(spec=Es512KeysManger)
    #     mock_es512_manager.load_keys.return_value = True
    #     mock_es512_manager.get_root_filename.return_value = 'test_key'
    #     mock_es512_manager.get_priv_cert.return_value = 'private_key'
    #     return mock_es512_manager

    def create_mock_es512_manager(self):
        mock_es512_manager = Mock()
        mock_es512_manager.load_keys.return_value = True
        mock_es512_manager.get_root_filename.return_value = 'test_key'

        # Mock a PEM-formatted key
        mock_es512_manager.get_priv_cert.return_value = \
"""-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAb4NAHON9nu/IwKu/
751QS2FwsNA2fxnfD3zNOifMx6v/LYZrVeihkAIfk9Tswk0U/0Rw2M1hWHqx5UNv
/1pf+IyhgYkDgYYABAAlTk7Hw7UyeJBIV0Jq8y41UeW6Erkz5YerO4uwsOD86jlq
bC/kVqUIHeiXgZc7CPYqb2EwtujIKxOo8sy/AQFRTwH42sm165gGW1s5QiTYpLg6
rEjN8U+hYkQWjQcOnC8ND+Vsx2nnGIj4nUgQbDr3FSj8DejppADoKYNok7qrHZWs
Wg==
-----END PRIVATE KEY-----
"""

        return mock_es512_manager

    @patch('pyjwt512.Es512KeysManger')
    def test_initialization(self, mock_es512):
        mock_es512.return_value = self.create_mock_es512_manager()
        jwt_creator = CreateJwtToken(self.cert_dir, self.valid_payload)
        self.assertIsNotNone(jwt_creator)

    @patch('pyjwt512.Es512KeysManger')
    def test_payload_validation_missing_key(self, mock_es512):
        mock_es512.return_value = self.create_mock_es512_manager()
        invalid_payload = self.valid_payload.copy()
        del invalid_payload['iss']
        with self.assertRaises(CreateTokenException):
            CreateJwtToken(self.cert_dir, invalid_payload)

    @patch('pyjwt512.Es512KeysManger')
    def test_payload_validation_invalid_type(self, mock_es512):
        mock_es512.return_value = self.create_mock_es512_manager()
        invalid_payload = self.valid_payload.copy()
        invalid_payload['uid'] = 'not_an_int'
        with self.assertRaises(CreateTokenException):
            CreateJwtToken(self.cert_dir, invalid_payload)

    @patch('pyjwt512.Es512KeysManger')
    def test_get_token_before_creation(self, mock_es512):
        mock_es512.return_value = self.create_mock_es512_manager()
        jwt_creator = CreateJwtToken(self.cert_dir, self.valid_payload)
        self.assertIsNone(jwt_creator.get_token())


