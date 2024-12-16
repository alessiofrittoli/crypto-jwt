# Crypto JSON Web Token 🔗

Version 0.1.0

## Lightweight TypeScript JSON Web Tokens library

JSON Web Tokens are an open, industry standard [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) method for representing claims securely between two parties.

Keep in mind that JSON Web Tokens can be easly decoded and they should **never** contains sensible informations!

JSON Web Tokens should be only used to store reference data (e.g. user ID). The token get then signed with the given "payload" and signature is verified to ensure the token hasn't been modified by third parties.

- Read more informations abot at [RFC 7519 - Internet Engineering Task Force (IETF)](https://datatracker.ietf.org/doc/html/rfc7519).

### Table of Contents

- [Getting started](#getting-started)
- [Supported Algrithms](#supported-algorithms)
- [Jwt Class API Reference](#jwt-class-api-reference)
	- [Constructor](#constructor)
	- [Properties](#properties)
	- [Methods](#methods)
	- [Example usage](#example-usage)
	- [Expiration](#expiration)
	- [Not before](#not-before)
	- [Type casting](#type-casting)
- [Error handling](#error-handling)
- [Contributing](#contributing)
- [Security](#security)
- [Credits](#made-with-)

---

### Getting started

Run the following command to start using `crypto-jwt` in your projects:

```bash
npm i @alessiofrittoli/crypto-jwt
```

or using `pnpm`

```bash
pnpm i @alessiofrittoli/crypto-jwt
```

---

### Supported Algorithms

The `Jwt` class supports different algorithms. You will find detailed informations in this documentation on how to use them so you can choose the best fit for you needs.

If no algorithm is specified, `HS256` is being used.

⚠️ Keep in mind that:

- you will need different key types based on the signing algorithm to use.
- usage of symmetric keys is insecure. Using asymmetric keys is recommended.

<details>

<summary>Supported algorithms</summary>

| Type         | JWK name | Description                                                           |
|--------------|----------|-----------------------------------------------------------------------|
| `none`       |          | No signing process is performed.                                      |
| `HMAC`       |          |                                                                       |
|              | `HS1`    | Token signed generated/verified with `HMAC` key and `SHA-1`.          |
|              | `HS256`  | Token signed generated/verified with `HMAC` key and `SHA-256`.        |
|              | `HS384`  | Token signed generated/verified with `HMAC` key and `SHA-384`.        |
|              | `HS512`  | Token signed generated/verified with `HMAC` key and `SHA-512`.        |
| `DSA`        |          |                                                                       |
|              | `DS1`    | Token signed generated/verified with `DSA` keys and `SHA-1`.          |
|              | `DS256`  | Token signed generated/verified with `DSA` keys and `SHA-256`.        |
|              | `DS384`  | Token signed generated/verified with `DSA` keys and `SHA-384`.        |
|              | `DS512`  | Token signed generated/verified with `DSA` keys and `SHA-512`.        |
| `EcDSA`      |          |                                                                       |
|              | `ES256`  | Token signed generated/verified with `EC` keys and `SHA-256`.         |
|              | `ES384`  | Token signed generated/verified with `EC` keys and `SHA-384`.         |
|              | `ES512`  | Token signed generated/verified with `EC` keys and `SHA-512`.         |
| `EdDSA`      |          |                                                                       |
|              | `EdDSA`  | Token signed generated/verified with `ed448` keys.                    |
|              | `EdDSA`  | Token signed generated/verified with `ed25519` keys.                  |
| `RSA`        |          |                                                                       |
|              | `RS1`    | Token signed generated/verified with `RSA` keys and `SHA-1`.          |
|              | `RS256`  | Token signed generated/verified with `RSA` keys and `SHA-256`.        |
|              | `RS384`  | Token signed generated/verified with `RSA` keys and `SHA-384`.        |
|              | `RS512`  | Token signed generated/verified with `RSA` keys and `SHA-512`.        |
| `RSASSA-PSS` |          |                                                                       |
|              | `PS256`  | Token signed generated/verified with `RSASSA-PSS` keys and `SHA-256`. |
|              | `PS384`  | Token signed generated/verified with `RSASSA-PSS` keys and `SHA-384`. |
|              | `PS512`  | Token signed generated/verified with `RSASSA-PSS` keys and `SHA-512`. |

</details>

---

### Jwt Class API Reference

#### Constructor

The `Jwt` class constructor accepts an `object` argument with the following properties:

<details>

<summary>Common properties</summary>

| Property | Type   | Default | Description |
|----------|--------|---------|-------------|
| `name` | `string` | `"JWT"` | The token name. This is used in error messages and intended for debugging purposes only. |
| `header` | `JsonWebToken.Header` | - | (Optional) The JOSE Header. |
|          |        |         |             |
| `header.alg` | `JsonWebToken.Algorithm` | `HS256` | Message authentication code algorithm. |
| `header.cty` | `string` | - | Content type - If nested signing or encryption is employed, it is recommended to set this to JWT; otherwise, omit this field. |
| `header.kid`  | `string` | - | Key ID - A hint indicating which key the client used to generate the token signature. The server will match this value to a key on file in order to verify that the signature is valid and the token is authentic. |
| `header.crit` | `string[]` | - | Critical - A list of headers that must be understood by the server in order to accept the token as valid. |
| `header.x5c` | `string \| string[]` | - | ⚠️ x.509 Certificate Chain - A certificate chain in RFC4945 format corresponding to the private key used to generate the token signature. The server will use this information to verify that the signature is valid and the token is authentic. - not supported yet. |
| `header.x5u` | `string \| string[]` | - | ⚠️ xx.509 Certificate Chain URL - A URL where the server can retrieve a certificate chain corresponding to the private key used to generate the token signature. The server will retrieve and use this information to verify that the signature is authentic. - not supported yet. |
| `header.x5t` | `string` | - | - |
| `header.jku` | `string` | - | - |
| `header['x5t#S256']` | `string` | - | - |
|          |        |         |             |
| `iat` | `string \| numbet \| Date` | current timestamp | (Optional) The token issuing Date time value in milliseconds past unix epoch, a Date string or a Date instance on which the JWT it has been issued. |
| `exp` | `string \| numbet \| Date` | - | (Optional) The token expiration Date time value in milliseconds past unix epoch, a Date string or a Date instance on and after which the JWT it's not accepted for processing. |
| `nbf` | `string \| numbet \| Date` | - | (Optional) The token Date time value in milliseconds past unix epoch, a Date string or a Date instance on which the JWT will start to be accepted for processing. |
| `jti` | `string` | - | JWT ID - Case-sensitive unique identifier of the token even among different issuers. |
| `iss` | `string` | - | Issuer - Identifies principal that issued the JWT. |
| `sub` | `string` | - | Subject - Identifies the subject of the JWT. |
| `aud` | `string` | - | Audience - Identifies the recipients that the JWT is intended for. Each principal intended to process the JWT must identify itself with a value in the audience claim. |

</details>

---

<details>

<summary>Signing properties</summary>

| Property | Type | Description                                                 |
|----------|------|-------------------------------------------------------------|
| `data`   | `T`  | The Payload data to sign into the token. Could be any non nullable value. |
| `key`    | `Sign.PrivateKey` | The token secret key used for HMAC or the PEM private key for RSA, ECDSA and RSASSA-PSS signing algorithms. |

</details>

---

<details>

<summary>Signature verification properties</summary>

| Property | Type     | Description       |
|----------|----------|-------------------|
| `token`  | `string` | The token string. |
| `key`    | `Sign.PublicKey` | The token secret key used for HMAC or the PEM public key for RSA, ECDSA and RSASSA-PSS sign verification algorithms. |

</details>

---

#### Properties

Here are listed the `Jwt` class instance accessible properties:

<details>

<summary>Properties</summary>

| Property  | Type                | Description     |
|-----------|---------------------|-----------------|
| `name`    | `string`            | The token name. |
| `iat`     | `Date \| undefined` | The token issuing Date. This properties defaults to the current timestamp when `Jwt.sign()` is called. |
| `exp`     | `Date \| undefined` | The token expiration Date. |
| `nbf`     | `Date \| undefined` | The token "not before" Date. |
| `aud`     | `string[] \| undefined` | Audience. This value is stored in the `payload` while signing the token or is being used to validate the `aud` property found in the token `payload` to validate. |
| `iss`     | `string \| undefined` | Issuer. This value is stored in the `payload` while signing the token or is being used to validate the `iss` property found in the token `payload` to validate. |
| `jti`     | `string \| undefined` | JWT ID. This value is stored in the `payload` while signing the token or is being used to validate the `jti` property found in the token `payload` to validate. |
| `header` | `JsonWebToken.Header` | The parsed JOSE header. |
| `payload` | `JsonWebToken.Payload<T>` | The parsed JWS payload. |
| `isVerified` | `boolean \| null` | Flag that is being set to `true \| false` when `Jwt.verify()` is executed. |
| `key`        | `Sign.PublicKey \| Sign.PrivateKey` | The key set when creating a new `Jwt` instance. |
| `token` | `string \| undefined` | The parsed JWT string. |

</details>

#### Methods

<details>

<summary>`Jwt.sign()`</summary>

The `Jwt.sign()` method synchronously generates and returns a new token string.

- It stores the result string in the `Jwt.token` property for further usage.
- The parsed `header` is being stored in the `Jwt.header` property.
- The `iat` property is being set to the current timestamp if none has been provided in the constructor.
- If the given `data` is an object, it's properties are being added to the `Jwt.payload` property.
- If the given `data` is not an object, it will be assigned to `Jwt.payload.data` property.
- stores the signature `Buffer` to the `Jwt.signature` property.

The `Jwt.sign()` method throws a new `Exception` when:

- no private key has been provided.
- no valid payload has been parsed.
- signature creation fails with the choosen algorithm due to invalid keys provided.

See [Error Handling](#error-handling) section for further informations.

</details>

---

<details>

<summary>`Jwt.verify()`</summary>

The `Jwt.verify()` method synchronously verifies a token string and returns `true` on signature verification success.

It throws a new `Exception` when:

- no public key has been provided.
- no token value has been provided.
- wrong formatted token has been provided.
- the token is expired or not yet in charge.
- expected values mismatch in the token header/payload (Issuer, Audience, algorithm...).
- signature verification failures due to an invalid signature (altered token).
- signature verification failures due to an invalid public key.

See [Error Handling](#error-handling) section for further informations.

</details>

---

### Example usage

#### Creating and verifying JSON Web Tokens

You can use the `Jwt` class to create or verify a JSON Web Token.

<details>

<summary>Creating a JWT with no signature</summary>

```ts
const jwt = new Jwt( {
	data	: 'Data encoded in the JWT payload.',
	header	: { alg: 'none' },
} )
console.log( jwt.sign() )
```

</details>

---

<details>

<summary>JWT with HMAC</summary>

#### `HS1`/`HS256`/`HS384`/`HS512`

To create a JWT using `HMAC` secrets you need to specify a secret key in the `key` field of the `Jwt` constructor.

The private key could be any `string`, KeyObject or Binary data. It is suggested to use a 256 bit string.

`HS1`/`HS256`/`HS384`/`HS512` (`HMAC` with `SHA-1`/`SHA-256`/`SHA-384`/`SHA-512`) is a symmetric keyed hashing algorithm that uses one secret key. Symmetric means two parties share the secret key. The key is used for both generating the signature and verifying it.

Be mindful when using a shared key; it can open potential vulnerabilities if the verifiers(multiple applications) are not appropriately secured.

##### Create the token

```ts
import crypto from 'crypto'
import Jwt from '@alessiofrittoli/crypto-jwt'

const secretKey = crypto.createSecretKey( Buffer.from( 'mysecretkey' ) )

const jwt = new Jwt( {
	data	: 'Data to be signed into the token.',
	key		: secretKey,
	header	: {
		alg: 'HS1', // HS1 | HS256 | HS384 | HS512
	},
} )
const signedJwt = jwt.sign()
```

##### Verify the token

```ts
const jwt = new Jwt( {
	token	: signedJwt,
	key		: secretKey,
	header	: {
		alg: 'HS1', // HS1 | HS256 | HS384 | HS512 -> expected algorithm.
	},
} )
const isValid = jwt.verify()
```

</details>

---

<details>

<summary>JWT with DSA</summary>

#### `DS1`/`DS256`/`DS384`/`DS512`

- Generate a keypair:

```ts
import crypto from 'crypto'

const keypair = crypto.generateKeyPairSync( 'dsa', {
	modulusLength		: 2048,
	divisorLength		: 256,
	publicKeyEncoding	: { type: 'spki', format: 'pem' },
	privateKeyEncoding	: { type: 'pkcs8', format: 'pem' },
} )
```

- Parse and sign a token:

```ts
import Jwt from '@alessiofrittoli/crypto-jwt'

const jwt = new Jwt( {
	data	: 'Data to be signed into the token.',
	key		: keypair.privateKey,
	header	: {
		alg: 'DS1', // DS1 | DS256 | DS384 | DS512
	},
} )
const signedJwt = jwt.sign()
```

- Parse and verify a token:

```ts
import Jwt from '@alessiofrittoli/crypto-jwt'

const jwt = new Jwt( {
	token	: signedJwt,
	key		: keypair.publicKey,
	header	: {
		alg: 'DS1', // DS1 | DS256 | DS384 | DS512 // expected algorithm
	},
} )
const isValid = jwt.verify()
```

</details>

---

<details>

<summary>JWT with EcDSA</summary>

#### `ES256`/`ES384`/`ES512`

Elliptic curve based JSON Web Signatures (JWS) provide integrity, authenticity and non-reputation to JSON Web Tokens (JWT).

The EC keys should be of sufficient length to match the required level of security. Note that while EC signatures are shorter than an RSA signature of equivalent strength, they may take more CPU time to verify.

#### ECDSA using P-256/384/521 and SHA-256/384/512

To generate a JWT signed with the `ES256`/`ES384`/`ES512` algorithm and ECDSA keys you need to generate an asymmetric keys as follow:

- Generate a keypair:

```ts
import crypto from 'crypto'

const es256keypair = crypto.generateKeyPairSync( 'ec', {
	namedCurve			: 'secp256k1',
	publicKeyEncoding	: { type: 'spki', format: 'pem' },
	privateKeyEncoding	: { type: 'pkcs8', format: 'pem' },
} )

const es384keypair = crypto.generateKeyPairSync( 'ec', {
	namedCurve			: 'secp384r1',
	publicKeyEncoding	: { type: 'spki', format: 'pem' },
	privateKeyEncoding	: { type: 'pkcs8', format: 'pem' },
} )

const es512keypair = crypto.generateKeyPairSync( 'ec', {
	namedCurve			: 'secp521r1',
	publicKeyEncoding	: { type: 'spki', format: 'pem' },
	privateKeyEncoding	: { type: 'pkcs8', format: 'pem' },
} )
```

- Parse and sign a token:

```ts
import Jwt from '@alessiofrittoli/crypto-jwt'

const es256Token = new Jwt( {
	data	: 'Data to be signed into the token.',
	header	: { alg: 'ES256' },
	key		: es256keypair.privateKey,
} ).sign()

const es384Token = new Jwt( {
	data	: 'Data to be signed into the token.',
	header	: { alg: 'ES384' },
	key		: es384keypair.privateKey,
} ).sign()

const es512Token = new Jwt( {
	data	: 'Data to be signed into the token.',
	header	: { alg: 'ES512' },
	key		: es512keypair.privateKey,
} ).sign()
```

- Parse and verify a token:

```ts
import Jwt from '@alessiofrittoli/crypto-jwt'

const es256Valid = new Jwt( {
	token	: es256Token,
	header	: { alg: 'ES256' }, // expected algorithm
	key		: es256keypair.publicKey,
} ).verify()

const es384Valid = new Jwt( {
	token	: es384Token,
	header	: { alg: 'ES384' }, // expected algorithm
	key		: es384keypair.publicKey,
} ).verify()

const es512Valid = new Jwt( {
	token	: es512Token,
	header	: { alg: 'ES512' }, // expected algorithm
	key		: es512keypair.publicKey,
} ).verify()
```

</details>

---

<details>

<summary>JWT with EdDSA</summary>

- Generate a keypair:

```ts
import crypto from 'crypto'

const ed448keypair = crypto.generateKeyPairSync( 'ed448', {
	publicKeyEncoding	: { type: 'spki', format: 'pem' },
	privateKeyEncoding	: { type: 'pkcs8', format: 'pem' },
} )

const ed25519keypair = crypto.generateKeyPairSync( 'ed25519', {
	publicKeyEncoding	: { type: 'spki', format: 'pem' },
	privateKeyEncoding	: { type: 'pkcs8', format: 'pem' },
} )
```

- Parse and sign a token:

```ts
import Jwt from '@alessiofrittoli/crypto-jwt'

const ed448Token = new Jwt( {
	data	: 'Data to be signed into the token.',
	header	: { alg: 'EdDSA' },
	key		: ed448keypair.privateKey,
} ).sign()

const ed25519Token = new Jwt( {
	data	: 'Data to be signed into the token.',
	header	: { alg: 'EdDSA' },
	key		: ed25519keypair.privateKey,
} ).sign()
```

- Parse and verify a token:

```ts
import Jwt from '@alessiofrittoli/crypto-jwt'

const ed448Valid = new Jwt( {
	token	: ed448Token,
	header	: { alg: 'EdDSA' }, // expected algorithm
	key		: ed448keypair.publicKey,
} ).verify()

const ed25519Valid = new Jwt( {
	token	: ed25519Token,
	header	: { alg: 'EdDSA' }, // expected algorithm
	key		: ed25519keypair.publicKey,
} ).verify()
```

</details>

---

<details>

<summary>JWT with RSA</summary>

#### `RS1`/`RS256`/`RS384`/`RS512`

- Generate a keypair:

```ts
import crypto from 'crypto'

const bytes		= 256
const keypair	= crypto.generateKeyPairSync( 'rsa', {
	modulusLength		: bytes * 8,
	publicKeyEncoding	: { type: 'spki', format: 'pem' },
	privateKeyEncoding	: { type: 'pkcs1', format: 'pem' },
} )
```

- Parse and sign a token:

```ts
import Jwt from '@alessiofrittoli/crypto-jwt'

const signedJwt = new Jwt( {
	data	: 'Data to be signed into the token.',
	header	: { alg: 'RS1' }, // RS1 | RS256 | RS384 | RS512
	key		: keypair.privateKey,
} ).sign()
```

- Parse and verify a token:

```ts
import Jwt from '@alessiofrittoli/crypto-jwt'

const validToken = new Jwt( {
	token	: signedJwt,
	header	: { alg: 'RS1' }, // RS1 | RS256 | RS384 | RS512
	key		: keypair.publicKey,
} ).verify()
```

</details>

---

<details>

<summary>JWT with RSASSA-PSS</summary>

#### `PS256`/`PS384`/`PS512`

- Generate a keypair:

```ts
import crypto from 'crypto'

const bytes = 256

/** RSASSA-PSS using `SHA-256` and MGF1 with `SHA-256` */
const rsapss256keypair = crypto.generateKeyPairSync( 'rsa-pss', {
	modulusLength		: bytes * 8,
	hashAlgorithm		: 'SHA-256',
	mgf1HashAlgorithm	: 'SHA-256',
	publicKeyEncoding	: { type: 'spki', format: 'pem' },
	privateKeyEncoding	: { type: 'pkcs8', format: 'pem' },
} )

/** RSASSA-PSS using `SHA-384` and MGF1 with `SHA-384` */
const rsapss384keypair = crypto.generateKeyPairSync( 'rsa-pss', {
	modulusLength		: bytes * 8,
	hashAlgorithm		: 'SHA-384',
	mgf1HashAlgorithm	: 'SHA-384',
	publicKeyEncoding	: { type: 'spki', format: 'pem' },
	privateKeyEncoding	: { type: 'pkcs8', format: 'pem' },
} )

/** RSASSA-PSS using `SHA-512` and MGF1 with `SHA-512` */
const rsapss512keypair = crypto.generateKeyPairSync( 'rsa-pss', {
	modulusLength		: bytes * 8,
	hashAlgorithm		: 'SHA-512',
	mgf1HashAlgorithm	: 'SHA-512',
	publicKeyEncoding	: { type: 'spki', format: 'pem' },
	privateKeyEncoding	: { type: 'pkcs8', format: 'pem' },
} )
```

- Parse and sign a token:

```ts
import Jwt from '@alessiofrittoli/crypto-jwt'

const rsapss256token = new Jwt( {
	data	: 'Data to be signed into the token.',
	header	: { alg: 'PS256' },
	key		: rsapss256keypair.privateKey,
} ).sign()

const rsapss384token = new Jwt( {
	data	: 'Data to be signed into the token.',
	header	: { alg: 'PS384' },
	key		: rsapss384keypair.privateKey,
} ).sign()

const rsapss512token = new Jwt( {
	data	: 'Data to be signed into the token.',
	header	: { alg: 'PS512' },
	key		: rsapss512keypair.privateKey,
} ).sign()
```

- Parse and verify a token:

```ts
import Jwt from '@alessiofrittoli/crypto-jwt'

const rsapss256Valid = new Jwt( {
	token	: rsapss256token,
	header	: { alg: 'PS256' },
	key		: rsapss256keypair.publicKey,
} ).verify()

const rsapss384Valid = new Jwt( {
	token	: rsapss384token,
	header	: { alg: 'PS384' },
	key		: rsapss384keypair.publicKey,
} ).verify()

const rsapss512Valid = new Jwt( {
	token	: rsapss512token,
	header	: { alg: 'PS512' },
	key		: rsapss512keypair.publicKey,
} ).verify()
```

</details>

---

#### Using keys that requires a passphrase

Most of asymmetric key pairs allows you to set a passphrase for the Private Key. This passphrase must be provided in order to use that key for generating a signature.

Let's assume we got this keypair with the following passphrase:

```ts
import crypto from 'crypto'

const bytes			= 256
const passphrase	= 'my-private-key-optional-passphrase'
const keypair		= crypto.generateKeyPairSync( 'rsa', {
	modulusLength		: 256 * 8,
	publicKeyEncoding	: { type: 'spki', format: 'pem' },
	privateKeyEncoding	: { type: 'pkcs1', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
} )
```

We can then sign a token as follow:

```ts
const jwt = new Jwt( {
	data	: 'Data to be signed into the token.',
	header	: { alg: 'RS1' },
	key		: {
		key			: keypair.privateKey,
		passphrase	: passphrase,
	},
} )
```

---

#### Expiration

By setting an expiration Date, the token will no longer be accepted on and after that Date. The `Jwt.verify()` method will then throw an Exception with the `ErrorCode.EXPIRED` code.

```ts
/** 5 minutes expiration token. */
const jwt = new Jwt( {
	exp: new Date().getTime() + ( 5 * 60 * 1000 ),
	...
} )
```

#### Not before

By setting "not before" Date, the token will not be accepted on and before that Date. The `Jwt.verify()` method will then throw an Exception with the `ErrorCode.TOO_EARLY` code.

```ts
/** token should not be accepted in the next 5 minutes. */
const jwt = new Jwt( {
	nbf: new Date().getTime() + ( 5 * 60 * 1000 ),
	...
} )
```

---

#### Type casting

By default the `Jwt` class will infer the type of the given `data` to the payload. So for example:

```ts
const jwt = new Jwt( {
	data: 'Data to be signed into the token.',
	...
} )
// `jwt` -> `Jwt<string>`
// `jwt.payload.data` -> `string`

const jwt = new Jwt( {
	data: [ 1, 2, 3 ],
	...
} )
// `jwt` -> `Jwt<number[]>`
// `jwt.payload.data` -> `number[]`

const jwt = new Jwt( {
	data: { property: 'value' },
	...
} )
// `jwt` -> `Jwt<{property: string}>`
// `jwt.payload` -> `{property: string} & JsonWebToken.JwsPayload`
```

For obvious reasons the type cannot be inferred when "reading" a token and `Jwt` class will fallback to the type of `unknown`.

```ts
new Jwt( {
	token: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoiQW4gdW5rbm93biB0eXBlIG9mIHBheWxvYWQiLCJpYXQiOjE3MzQzNzc3MTJ9.qptazZOXfAgFbMpVlPdGa6RstKlA945_-Qm1PhfmPIQ',
	...
} ) // -> `Jwt<unknown>`
```

The `Jwt` class allows you to assing a custom type to the `T` parameter so that type can securely inferred to the payload data.

```ts
new Jwt<User>( {
	data: { id: 1 },
	...
} ).payload // -> `User & JsonWebToken.JwsPayload`

const jwt = new Jwt<User>( {
	token: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwiaWF0IjoxNzM0Mzc4MDc0fQ.jt3-bjXe8NEyr9MEk5cvzCM_M_YcG9tpaWwKPhnIK8c',
	...
} )
// `jwt.payload` // -> `User & JsonWebToken.JwsPayload`
// `jwt.payload.id` // -> safe type access
```

---

### Error handling

This module throws a new `Exception` when an error occures providing an error code that will help in error handling.

The `ErrorCode` enumerator can be used to handle different errors with ease.

<details>

<summary>`ErrorCode` enum</summary>

| Constant              | Description                                              |
|-----------------------|----------------------------------------------------------|
| `UNKNOWN`             | Thrown when `Jwt.sign()` encounters an unexpected error. |
| `NO_PRIVATEKEY`       | Thrown when `Jwt.sign()` has no private key. |
| `EMPTY_VALUE`         | Thrown when: |
|                       | `Jwt.sign()` has no `payload` to sign. |
|                       | `Jwt.verify()` has no `token` to verify. |
| `WRONG_FORMAT`        | Thrown when `Jwt.verify()` encounter a malformed JWT. |
| `NO_HEADER`           | Thrown when `Jwt.verify()` has no JOSE Header to validate. |
| `WRONG_HEADER`        | Thrown when `Jwt.verify()` cannot parse JOSE Header. |
| `WRONG_ALGO`          | Thrown when `Jwt.verify()` finds an unexpected `alg` field in the given `token` JOSE Header. |
| `WRONG_KID`           | Thrown when `Jwt.verify()` finds an unexpected `kid` field in the given `token` JOSE Header. |
| `WRONG_JWS`           | Thrown when `Jwt` couldn't parse the given `token` payload. |
| `EXPIRED`             | Thrown when `Jwt.verify()` finds an expired token. |
| `TOO_EARLY`           | Thrown when `Jwt.verify()` verifies a token that cannot be still processed. |
| `UNEXPECTED_ISSUER`   | Thrown when `Jwt.verify()` finds an unexpected `iss` field in the given `token` payload. |
| `UNEXPECTED_AUDIENCE` | Thrown when `Jwt.verify()` finds an unexpected `aud` field in the given `token` payload. |
| `UNEXPECTED_JTI`      | Thrown when `Jwt.verify()` finds an unexpected `jti` field in the given `token` payload. |
| `NO_SIGN`             | Thrown when `Jwt.verify()` doesn't find any signature in the given `token`. |
| `UNEXPECTED_SIGN`     | Thrown when `Jwt.verify()` finds an unexpected signature in the given `token` (expected `none` algorithm). |
| `INVALID_SIGN`        | Thrown when `Jwt.verify()` receives an invalid signature (altered JWT). |
| `NO_PUBLICKEY`        | Thrown when `Jwt.verify()` has no public key. |

</details>

---

<details>

<summary>Example usage</summary>

```ts
import Exception from '@alessiofrittoli/exception'
import { ErrorCode } from '@alessiofrittoli/crypto-jwt/error'

try {
	new Jwt( {
		token: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid'
	} ) // will throw error with code: ErrorCode.WRONG_HEADER
} catch ( error ) {
	if ( Exception.isException( error ) ) {
		switch ( error.code ) {
			case ErrorCode.WRONG_JWS:
				// malformed JWT payload
				break
			// ... other cases here
			default:
				// unknown error
		}
	}
}
```

</details>

---

<!-- ### Development

#### Install depenendencies

```bash
npm install
```

or using `pnpm`

```bash
pnpm i
```

#### Build your source code

Run the following command to build code for distribution.

```bash
pnpm build
```

#### [ESLint](https://www.npmjs.com/package/eslint)

warnings / errors check.

```bash
pnpm lint
```

#### [Jest](https://npmjs.com/package/jest)

Run all the defined test suites by running the following:

```bash
# Run tests and watch file changes.
pnpm test

# Run tests in a CI environment.
pnpm test:ci
```

You can eventually run specific suits like so:

```bash
pnpm test:jest
pnpm test:jest:jsdom
```

--- -->

### Contributing

Contributions are truly welcome!\
Please refer to the [Contributing Doc](./CONTRIBUTING.md) for more information on how to start contributing to this project.

---

### Security

If you believe you have found a security vulnerability, we encourage you to **_responsibly disclose this and NOT open a public issue_**. We will investigate all legitimate reports. Email `security@alessiofrittoli.it` to disclose any security vulnerabilities.

### Made with ☕

<table style='display:flex;gap:20px;'>
	<tbody>
		<tr>
			<td>
				<img src='https://avatars.githubusercontent.com/u/35973186' style='width:60px;border-radius:50%;object-fit:contain;'>
			</td>
			<td>
				<table style='display:flex;gap:2px;flex-direction:column;'>
					<tbody>
						<tr>
							<td>
								<a href='https://github.com/alessiofrittoli' target='_blank' rel='noopener'>Alessio Frittoli</a>
							</td>
						</tr>
						<tr>
							<td>
								<small>
									<a href='https://alessiofrittoli.it' target='_blank' rel='noopener'>https://alessiofrittoli.it</a> |
									<a href='mailto:info@alessiofrittoli.it' target='_blank' rel='noopener'>info@alessiofrittoli.it</a>
								</small>
							</td>
						</tr>
					</tbody>
				</table>
			</td>
		</tr>
	</tbody>
</table>