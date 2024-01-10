import jwt
import time
from pyjwt512.Es512KeysManger import Es512KeysManger
from pyjwt512.Exceptions import CreateTokenException


class CreateJwtToken:
    def __init__(self, cert_dir: str, payload: dict) -> None:
        """
        Initialize the JWT Token creator with a directory for certificates and a payload.
        The payload must include "iss" (issuer), "aud" (audience), and "uid" (user identifier).

        Params:
            cert_dir: Directory with keys.
            payload: Payload with required values.
        """
        self.__check_payload(payload)
        self.__payload = payload

        self.__cert_dir = cert_dir
        self.__token: str = None

    def get_token(self) -> str | None:
        """
        Returns the generated token.

        Returns:
            str: The JWT token, or None if not yet created.
        """
        return self.__token

    def create(self) -> bool:
        """
        Create a JWT Token. ES512 keys must exist or be created before calling this method.

        Returns:
            bool: True if the token was successfully created.

        Raises:
            CreateTokenException: If there's an error in token creation.
        """
        # load last keys
        es512 = Es512KeysManger()
        if not es512.load_keys(cert_dir=self.__cert_dir, public_only=False):
            raise CreateTokenException("Failed to load ES512 keys for token creation.")

        # add dactual iat
        self.__payload["iat"] = int(time.time())  # actual unix timestamp
        # set kid
        headers = {"kid": es512.get_root_filename()}

        self.__token = jwt.encode(
            self.__payload, es512.get_priv_cert(), algorithm="ES512", headers=headers
        )

        return True

    def __check_payload(self, payload: dict) -> None | CreateTokenException:
        """
        Checks if the payload contains all required keys with valid types.

        Params:
            payload: The payload to check.

        Raises:
            CreateTokenException: If required payload arguments are missing or invalid.
        """
        required_keys = {
            "iss": str,  # Issuer expected to be a string
            "aud": str,  # Audience expected to be a string
            "uid": int,  # User ID expected to be an integer
        }

        for key, expected_type in required_keys.items():
            if key not in payload:
                raise CreateTokenException(
                    f"Missing required payload argument: '{key}'."
                )
            if not isinstance(payload[key], expected_type):
                raise CreateTokenException(
                    f"Incorrect type for payload argument '{key}': Expected {expected_type.__name__}, got {type(payload[key]).__name__}."
                )
