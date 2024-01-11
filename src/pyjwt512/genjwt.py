#!/usr/bin/env python3
import os
import fire
import datetime
from datetime import timezone
from pyjwt512.Exceptions import CreateTokenException, InvalidTokenException
from pyjwt512.CreateJwtToken import CreateJwtToken
from pyjwt512.Es512KeysManger import Es512KeysManger
from pyjwt512.VerifyJwtToken import VerifyJwtToken


class jwt_tokens:
    """
    Generate JWT, Create new ECDSA SHA-512 keys or validate a token with key.
    """

    def token(
        self,
        dir: str,
        iss: str,
        aud: str,
        uid: int,
        exp: str = None,
        custom: dict = None,
    ) -> None:
        """
        Create new JWT token.

        Required arguments:
            --dir=<path>: str
            --iss=<issuer>: str
            --aud=<audince>: str
            --uid=<id>: int
        Optional arguments:
            --exp=<expire after>: str
            --custom=<custom data>: dict
            examples:
                --exp="minutes=5" - valid units: "seconds=int" | "minutes=int" | "days=int" | "hours=int" | "weeks=int"
                --custom="{var1:value1,var2:value2,...}"
        """
        if not os.path.exists(dir):
            return f"Error: Is there a {dir} directory?"

        # basic payload
        payload = {
            "iss": iss,
            "aud": aud,
            "uid": uid,
        }

        # add expiration if possible
        if exp:
            # check format
            if not ("=" in exp):
                return f"Error: --exp={exp} bad format."
            parts = exp.split("=")
            valid_units = {"seconds", "minutes", "days", "hours", "weeks"}
            # check valid units
            if not parts[0] in valid_units:
                return f'Error: "{parts[0]}" in --exp is not in valid units: {valid_units}.'
            # check neno zero value
            if not int(parts[1]) > 0:
                return f"Error: --exp={exp} value must be greater zero."
            # Compute expiration and add to payload
            kwargs = {parts[0]: int(parts[1])}
            payload["exp"] = datetime.datetime.now(
                tz=timezone.utc
            ) + datetime.timedelta(**kwargs)

        # add custom to payload if exist and is dist
        if custom:
            if not isinstance(custom, dict):
                return f"Error: --custom must be a dict."
            for key, value in custom.items():
                if key not in payload:
                    payload[key] = value

        # create token
        try:
            create_token = CreateJwtToken(cert_dir=dir, payload=payload)
            if create_token.create():
                return f"Token: {create_token.get_token()}"
        except CreateTokenException as e:
            return f"CreateTokenException: {e}"

    def keys(self, dir: str) -> None:
        """
        Create new PEM KEYS and save it in DIR

        Required argument:
            --dir=<path>: str
        """
        if not os.path.exists(dir):
            return f"Error: Is there a {dir} directory?"

        # create keys
        es512 = Es512KeysManger()
        es512.generate_new_keys()
        if not es512.save_new_keys(cert_dir=dir):
            return f"Error: Keys not generated."

        k_priv = os.path.join(dir, f"{es512.get_root_filename()}.pem")
        k_pub = os.path.join(dir, f"{es512.get_root_filename()}-public.pem")

        return f"New keys has been saved in {k_pub} and {k_priv} files."

    def check(self, token: str, dir: str, aud: str) -> None:
        """
        Check validity of a token

        Required arguments:
            --dir=<path>: str
            --aud=<audience>: str
            --token=<jwt token>: str
        """
        if not os.path.exists(dir):
            return f"Error: Is there a {dir} directory?"

        try:
            jwt_token = VerifyJwtToken()
            if jwt_token.validate(token=token, audience=aud, cert_dir=dir):
                return f"Token is valid.\n{jwt_token}"
        except InvalidTokenException as e:
            return f"InvalidTokenException: {e}"


def run():
    fire.Fire(jwt_tokens)


if __name__ == "__main__":
    run()
