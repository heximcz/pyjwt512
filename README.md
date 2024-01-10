# Simple JWT Manager for ES512

A simple JWT manager with ES512 key management, token generation and validation with options to integrate into your project or use in the cli.

## Install

`pip install PyJwt512`

## Usage in CLI

```
# generate new ES512 private and public key
$ pyjwt512 keys --dir=<path>

# validate a token
$ pyjwt512 check --dir=<path> --aud=<audience> --token=<jwt token>

# get new token
$ pyjwt512 token --dir=<path> --iss=<issuer> --aud=<audince> --uid=<client id>
```

For example:

```
$ pyjwt512 keys --dir=/tmp
New keys has been saved in /tmp/001581e99ba047bca44871c4248f689c-public.pem and /tmp/001581e99ba047bca44871c4248f689c.pem files.
```
```
$ pyjwt512 token --dir=/tmp --iss=https://example.com --aud=service.example.com --uid=1234
Token:  eyJhbGciOiJF...
```
```
$ pyjwt512 check --dir=/tmp --aud=service.example.com --token=eyJhbGciOiJF...
Token is valid.
iss : https://example.com, aud : service.example.com, iat : 1704896624, uid : 1234, kid : 001581e99ba047bca44871c4248f689c
```

Print help:
```
$ pyjwt512
$ pyjwt512 keys --help
$ pyjwt512 token --help
$ pyjwt512 check --help
```

## Usage in a script

```python
import os
from pyjwt512 import Es512KeysManger

# Create new keys
es512 = Es512KeysManger()
es512.generate_new_keys()

cert_dir = "/tmp"

if not es512.save_new_keys(cert_dir=cert_dir):
    print(f"Error generating keys")

k_priv = os.path.join(cert_dir, f"{es512.get_root_filename()}.pem")
k_pub = os.path.join(cert_dir, f"{es512.get_root_filename()}-public.pem")

print(f"New keys has been saved in {k_pub} and {k_priv} file.")

```

```python
from pyjwt512 import CreateTokenException
from pyjwt512 import CreateJwtToken

# Create new token
payload = {
    "iss": "iss",
    "aud": "aud",
    "uid": 123,
}
try:
    create_token = CreateJwtToken(cert_dir="/tmp", payload=payload)
    if create_token.create():
        print(f"Token: {create_token.get_token()}")
except CreateTokenException as e:
    print(f"CreateTokenException: {str(e)}")
```

```python
from pyjwt512 import InvalidTokenException
from pyjwt512 import VerifyJwtToken

# Valid a token
jwt_token = VerifyJwtToken()
try:
    if jwt_token.validate(token="any token", audience="any audience", cert_dir="/tmp"):
        print(f"Token is valid.")
        print(f"{jwt_token}")
except InvalidTokenException as e:
    print(f"InvalidTokenException: {str(e)}")
```
