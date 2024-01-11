import os
import jwt
from pyjwt512.Exceptions import InvalidTokenException


class VerifyJwtToken:
    """
    A class for verifying JSON Web Tokens (JWT) using the ES384 algorithm.

    Attributes:
        iss (str): Issuer of the JWT.
        aud (str): Audience of the JWT.
        iat (str): Issued At time of the JWT.
        uid (int): User ID in the JWT.
        kid (str): Key ID for the public key used in verification.

    Methods:
        validate(token, audience, cert_dir): Validates the JWT. Returns True if valid, otherwise raises InvalidTokenExeption.
        __str__(): Returns a string representation of the object.
    """

    def __init__(self) -> None:
        self.__iss: str = None
        self.__aud: str = None
        self.__iat: str = None
        self.__uid: int = None
        self.__kid: str = None
        self.__claimset: dict = None
        self.__header: dict = None

    def get_iss(self) -> str | None:
        """Get iss"""
        return self.__iss

    def get_aud(self) -> str | None:
        """Get sud"""
        return self.__aud

    def get_iat(self) -> str | None:
        """Get iat"""
        return self.__iat

    def get_uid(self) -> int | None:
        """Get uid"""
        return self.__uid

    def get_kid(self) -> str | None:
        """Get kid"""
        return self.__kid
    
    def get_header(self) -> dict | None:
        """Get calimset"""
        return self.__header
    
    def get_claimset(self) -> dict | None:
        """Get calimset"""
        return self.__claimset

    def validate(
        self, token: str, audience: str, cert_dir: str
    ) -> bool | InvalidTokenException:
        """
        Validates a JWT token using the ES512 algorithm.

        This function attempts to verify the given JWT token by checking its signature
        with the public key specified by the 'kid' (Key ID) field in the token. The
        public key is retrieved from the provided certificate directory. The function
        also verifies that the token's audience matches the provided audience.

        Params:

            token (str): The JWT token to be validated.

            audience (str): The expected audience value that the token should contain.
            
            cert_dir (str): The directory where the public key PEM file is located.
            The public key file is expected to be named as '<kid>-public.pem',
            where '<kid>' is the Key ID obtained from the token.

        Returns:
            bool: True if the token is successfully validated, False otherwise.

        Raises:
            InvalidTokenException: If the token cannot be decoded, if the Key ID ('kid')
                                   is missing, if the public key file cannot be found or read,
                                   or if the token's signature, audience, issuer, etc., are
                                   invalid or do not match the expected values.

        Example::

            try:
                verifier = VerifyJwtToken()
                is_valid = verifier.validate(token="your.jwt.token", audience="yourAudience", cert_dir="/path/to/cert/dir")
                if is_valid:
                    print('Token is valid.')
                else:
                    print('Token is invalid.')
            except InvalidTokenException as e:
                print(f'Token validation failed: {e}')
        """

        try:
            self.__header = jwt.get_unverified_header(token)
            self.__kid = self.__header["kid"]
        except jwt.exceptions.DecodeError as e:
            raise InvalidTokenException(e)

        # Load public key
        try:
            public_key_path = os.path.join(cert_dir, f"{self.__kid}-public.pem")
            with open(public_key_path, "r") as f:
                public_key = f.read()
        except IOError as e:
            raise InvalidTokenException(str(e))

        try:
            # jwt token validation
            decoded_jwt = jwt.decode(
                token, public_key, audience=audience, algorithms=["ES512"]
            )
            self.__iss = decoded_jwt["iss"]
            self.__aud = decoded_jwt["aud"]
            self.__iat = decoded_jwt["iat"]
            self.__uid = decoded_jwt["uid"]
            self.__claimset = decoded_jwt
        except jwt.InvalidTokenError as e:
            raise InvalidTokenException(str(e))
        except Exception as e:
            raise InvalidTokenException(str(e))

        return True

    def __str__(self) -> str:
        return f"Header: {self.__header}\nClaimset: {self.__claimset}"
