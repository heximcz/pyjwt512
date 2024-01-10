#!/usr/bin/env python3
import os
import fire
from pyjwt512.Exceptions import CreateTokenException, InvalidTokenException
from pyjwt512.CreateJwtToken import CreateJwtToken
from pyjwt512.Es512KeysManger import Es512KeysManger
from pyjwt512.VerifyJwtToken import VerifyJwtToken


class jwt_tokens:
    """
    Generate JWT, Create new ECDSA SHA-512 keys or validate a token with key.
    """

    def token(self, dir: str, iss: str, aud: str, uid: int) -> None:
        """
        Create new JWT token.

        Required arguments:
            --dir=<path>: str
            --iss=<issuer>: str
            --aud=<audince>: str
            --uid=<id>: int
        """
        if os.path.exists(dir) and uid and iss and aud:
            payload = {
                "iss": iss,
                "aud": aud,
                "uid": uid,
            }
            try:
                create_token = CreateJwtToken(cert_dir=dir, payload=payload)
                if create_token.create():
                    print("Token: ", create_token.get_token())
            except CreateTokenException as e:
                print(f"CreateTokenException: {e}")
        else:
            print(f"Args error. Check: --dir={dir} --iss={iss} --aud={aud} --uid={uid}")

    def keys(self, dir: str) -> None:
        """
        Create new PEM KEYS and save it in DIR

        Required argument:
            --dir=<path>
        """
        if os.path.exists(dir):
            es512 = Es512KeysManger()
            es512.generate_new_keys()
            if not es512.save_new_keys(cert_dir=dir):
                print(f"ERROR: Keys not generated.")
            k_priv = os.path.join(dir, f"{es512.get_root_filename()}.pem")
            k_pub = os.path.join(dir, f"{es512.get_root_filename()}-public.pem")
            print(f"New keys has been saved in {k_pub} and {k_priv} files.")
        else:
            print(f"Args error. Check: --dir={dir}")

    def check(self, token: str, dir: str, aud: str) -> None:
        """
        Check validity of a token

        Required arguments:
            --dir=<path>: str
            --aud=<audience>: str
            --token=<jwt token>: str
        """
        if os.path.exists(dir) and token and aud:
            jwt_token = VerifyJwtToken()
            try:
                if jwt_token.validate(token=token, audience=aud, cert_dir=dir):
                    print(f"Token is valid.")
                    print(jwt_token)
            except InvalidTokenException as e:
                print(f"InvalidTokenException: {e}")
        else:
            print(f"Args error. Check: --dir={dir} --token={token[:8]}...  --aud={aud}")

def run():
    fire.Fire(jwt_tokens)

if __name__ == "__main__":
    run()

#if __name__ == "__main__":
#    fire.Fire(jwt_tokens)
