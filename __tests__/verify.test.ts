import crypto from 'crypto'
import { Jwt } from '@/index'

const secretKey = crypto.createSecretKey( Buffer.from( 'mysecretkey' ) )

describe( 'Jwt.verify()', () => {

	it( 'supports string data payload', () => {

		const token = new Jwt( {
			data: 'Data to be signed into the token.',
			key	: secretKey,
		} ).sign()

		const jwt = new Jwt<string>( {
			token: token,
		} )

		expect( typeof jwt.payload.data ).toBe( 'string' )

	} )


	it( 'supports object data payload', () => {

		const token = new Jwt<{ property: string }>( {
			data: { property: 'Data to be signed into the token.' },
			key	: secretKey,
		} ).sign()

		const jwt = new Jwt<{ property: string }>( {
			token: token,
		} )

		expect( 'property' in jwt.payload ).toBe( true )
		expect( jwt.payload.property ).toBe( 'Data to be signed into the token.' )

	} )


	it( 'verifies Issuer', () => {
		const token = new Jwt( {
			data: 'Data to be signed into the token.',
			key	: secretKey,
			iss	: 'alessiofrittoli.it',
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			key		: secretKey,
			iss		: 'alessiofrittoli.it',
		} )

		expect( jwt.verify() ).toBe( true )
	} )


	it( 'verifies JWT ID', () => {
		const token = new Jwt( {
			data: 'Data to be signed into the token.',
			key	: secretKey,
			jti	: 'a445be00-7d03-4502-9722-2b75d1bdc0ff',
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			key		: secretKey,
			jti		: 'a445be00-7d03-4502-9722-2b75d1bdc0ff',
		} )

		expect( jwt.verify() ).toBe( true )
	} )


	it( 'verifies Audience', () => {
		const requestOrigin = 'localhost:3000'

		const token = new Jwt( {
			data: 'Data to be signed into the token.',
			key	: secretKey,
			aud	: [ requestOrigin ],
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			key		: secretKey,
			aud		: [ requestOrigin ],
		} )

		expect( jwt.verify() ).toBe( true )
	} )


	it( 'verifies "not before"', () => {
		const token = new Jwt( {
			key	: secretKey,
			data: 'Data to be signed into the token.',
			nbf	: new Date( new Date().getTime() + ( 5 * 60 * 1000 ) ),
		} ).sign()

		let pass = false

		try {
			new Jwt( {
				token	: token,
				key		: secretKey,
			} ).verify()
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		} catch ( error ) {
			pass = true
		}

		expect( pass ).toBe( true )
	} )


	it( 'verifies expiration', () => {
		let pass = false
		const token = new Jwt( {
			key	: secretKey,
			data: 'Data to be signed into the token.',
			iat	: new Date( new Date().getTime() - ( 5 * 60 * 1000 ) ),
			exp	: new Date( new Date().getTime() - ( 2 * 60 * 1000 ) ),
		} ).sign()
		try {
			new Jwt( {
				token	: token,
				key		: secretKey,
			} ).verify()
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		} catch ( error ) {
			pass = true
		}

		expect( pass ).toBe( true )
	} )

} )


describe( 'Jwt.verify() - none', () => {

	it( 'verifies a token with no signature', () => {
		const token = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'none' },
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			header	: { alg: 'none' },
		} )

		expect( jwt.verify() ).toBe( true )
		expect( jwt.signature ).toBe( null )
	} )

} )


describe( 'Jwt.verify() - HMAC', () => {

	it( 'verifies a token with HS1', () => {
		const token = new Jwt( {
			key		: secretKey,
			data	: 'Data to be signed into the token.',
			header	: { alg: 'HS1' },
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			key		: secretKey,
			header	: { alg: 'HS1' },
		} )

		expect( jwt.verify() ).toBe( true )
	} )


	it( 'verifies a token with HS256', () => {
		const token = new Jwt( {
			key		: secretKey,
			data	: 'Data to be signed into the token.',
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			key		: secretKey,
		} )

		expect( jwt.verify() ).toBe( true )
	} )


	it( 'verifies a token with HS384', () => {
		const token = new Jwt( {
			key		: secretKey,
			data	: 'Data to be signed into the token.',
			header	: { alg: 'HS384' },
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			key		: secretKey,
			header	: { alg: 'HS384' },
		} )

		expect( jwt.verify() ).toBe( true )
	} )


	it( 'verifies a token with HS512', () => {
		const token = new Jwt( {
			key		: secretKey,
			data	: 'Data to be signed into the token.',
			header	: { alg: 'HS512' },
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			key		: secretKey,
			header	: { alg: 'HS512' },
		} )

		expect( jwt.verify() ).toBe( true )
	} )

} )


describe( 'Jwt.verify() - DSA', () => {

	const passphrase = 'my-private-key-optional-passphrase'
	const keypair = crypto.generateKeyPairSync( 'dsa', {
		modulusLength		: 2048,
		divisorLength		: 256,
		publicKeyEncoding	: { type: 'spki', format: 'pem' },
		privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' }
	} )

	it( 'verifies a token with DS1', () => {
		const token = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'DS1' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			header	: { alg: 'DS1' },
			key		: keypair.publicKey,
		} )

		expect( jwt.verify() ).toBe( true )
	} )


	it( 'verifies a token with DS256', () => {
		const token = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'DS256' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			header	: { alg: 'DS256' },
			key		: keypair.publicKey,
		} )

		expect( jwt.verify() ).toBe( true )
	} )


	it( 'verifies a token with DS384', () => {
		const token = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'DS384' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			header	: { alg: 'DS384' },
			key		: keypair.publicKey,
		} )

		expect( jwt.verify() ).toBe( true )
	} )


	it( 'verifies a token with DS512', () => {
		const token = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'DS512' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			header	: { alg: 'DS512' },
			key		: keypair.publicKey,
		} )

		expect( jwt.verify() ).toBe( true )
	} )

} )


describe( 'Jwt.verify() - EcDSA', () => {

	const passphrase = 'my-private-key-optional-passphrase'

	it( 'verifies a token with ES256', () => {
		const keypair = crypto.generateKeyPairSync( 'ec', {
			namedCurve			: 'secp256k1',
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const token = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'ES256' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			header	: { alg: 'ES256' },
			key		: keypair.publicKey,
		} )

		expect( jwt.verify() ).toBe( true )
	} )


	it( 'verifies a token with ES384', () => {
		const keypair = crypto.generateKeyPairSync( 'ec', {
			namedCurve			: 'secp384r1',
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const token = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'ES384' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			header	: { alg: 'ES384' },
			key		: keypair.publicKey,
		} )

		expect( jwt.verify() ).toBe( true )
	} )


	it( 'verifies a token with ES512', () => {
		const keypair = crypto.generateKeyPairSync( 'ec', {
			namedCurve			: 'secp521r1',
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const token = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'ES512' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			header	: { alg: 'ES512' },
			key		: keypair.publicKey,
		} )

		expect( jwt.verify() ).toBe( true )
	} )

} )


describe( 'Jwt.verify() - EdDSA', () => {

	const passphrase = 'my-private-key-optional-passphrase'

	it( 'verifies a token with ed448', () => {
		const keypair = crypto.generateKeyPairSync( 'ed448', {
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' }
		} )

		const token = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'EdDSA' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			header	: { alg: 'EdDSA' },
			key		: keypair.publicKey,
		} )

		expect( jwt.verify() ).toBe( true )
	} )


	it( 'verifies a token with ed25519', () => {
		const keypair = crypto.generateKeyPairSync( 'ed25519', {
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' }
		} )

		const token = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'EdDSA' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			header	: { alg: 'EdDSA' },
			key		: keypair.publicKey,
		} )

		expect( jwt.verify() ).toBe( true )
	} )

} )


describe( 'Jwt.verify() - RSA', () => {

	const bytes			= 256
	const passphrase	= 'my-private-key-optional-passphrase'
	const keypair		= crypto.generateKeyPairSync( 'rsa', {
		modulusLength		: bytes * 8,
		publicKeyEncoding	: { type: 'spki', format: 'pem' },
		privateKeyEncoding	: { type: 'pkcs1', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
	} )


	it( 'verifies a token with RS1', () => {
		const token = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'RS1' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			header	: { alg: 'RS1' },
			key		: keypair.publicKey,
		} )

		expect( jwt.verify() ).toBe( true )
	} )


	it( 'verifies a token with RS256', () => {
		const token = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'RS256' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			header	: { alg: 'RS256' },
			key		: keypair.publicKey,
		} )

		expect( jwt.verify() ).toBe( true )
	} )


	it( 'verifies a token with RS384', () => {
		const token = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'RS384' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			header	: { alg: 'RS384' },
			key		: keypair.publicKey,
		} )

		expect( jwt.verify() ).toBe( true )
	} )


	it( 'verifies a token with RS512', () => {
		const token = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'RS512' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			header	: { alg: 'RS512' },
			key		: keypair.publicKey,
		} )

		expect( jwt.verify() ).toBe( true )
	} )

} )


describe( 'Jwt.verify() - RSASSA-PSS', () => {

	const bytes			= 256
	const passphrase	= 'my-private-key-optional-passphrase'


	it( 'verifies a token with PS256', () => {

		const hash = 'SHA-256'
		/** RSASSA-PSS using `hash` and MGF1 with `hash` */
		const keypair = crypto.generateKeyPairSync( 'rsa-pss', {
			modulusLength		: bytes * 8,
			hashAlgorithm		: hash,
			mgf1HashAlgorithm	: hash,
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const token = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'PS256' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			header	: { alg: 'PS256' },
			key		: keypair.publicKey,
		} )

		expect( jwt.verify() ).toBe( true )
	} )


	it( 'verifies a token with PS384', () => {

		const hash = 'SHA-384'
		/** RSASSA-PSS using `hash` and MGF1 with `hash` */
		const keypair = crypto.generateKeyPairSync( 'rsa-pss', {
			modulusLength		: bytes * 8,
			hashAlgorithm		: hash,
			mgf1HashAlgorithm	: hash,
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const token = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'PS384' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			header	: { alg: 'PS384' },
			key		: keypair.publicKey,
		} )

		expect( jwt.verify() ).toBe( true )
	} )


	it( 'verifies a token with PS512', () => {

		const hash = 'SHA-512'
		/** RSASSA-PSS using `hash` and MGF1 with `hash` */
		const keypair = crypto.generateKeyPairSync( 'rsa-pss', {
			modulusLength		: bytes * 8,
			hashAlgorithm		: hash,
			mgf1HashAlgorithm	: hash,
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const token = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'PS512' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} ).sign()

		const jwt = new Jwt( {
			token	: token,
			header	: { alg: 'PS512' },
			key		: keypair.publicKey,
		} )

		expect( jwt.verify() ).toBe( true )
	} )

} )