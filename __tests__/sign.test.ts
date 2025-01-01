import crypto from 'crypto'
import { Jwt } from '@/index'

const secretKey = crypto.createSecretKey( Buffer.from( 'mysecretkey' ) )

describe( 'Jwt.sign()', () => {

	it( 'supports string data payload', () => {

		const jwt = new Jwt( {
			data: 'Data to be signed into the token.',
			key	: secretKey,
		} )

		expect( typeof jwt.payload.data ).toBe( 'string' )

	} )


	it( 'supports object data payload', () => {

		const jwt = new Jwt<{ property: string }>( {
			key	: secretKey,
			data: {
				property: 'Data to be signed into the token.',
			},
		} )

		expect( 'property' in jwt.payload ).toBe( true )
		expect( jwt.payload.property ).toBe( 'Data to be signed into the token.' )

	} )

} )


describe( 'Jwt.sign() - none', () => {

	it( 'create a token with no signature', () => {
		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'none' },
		} )
		
		const token = jwt.sign()
		const parts = token.split( '.' )
		
		expect( parts.length ).toBe( 2 )
	} )

} )


describe( 'Jwt.sign() - HMAC', () => {

	it( 'signs a token with HS1', () => {
		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			key		: secretKey,
			header	: { alg: 'HS1' },
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )


	it( 'signs a token with HS256', () => {
		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			key		: secretKey,
			header	: { alg: 'HS256' },
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )


	it( 'signs a token with HS384', () => {
		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			key		: secretKey,
			header	: { alg: 'HS384' },
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )


	it( 'signs a token with HS512', () => {
		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			key		: secretKey,
			header	: { alg: 'HS512' },
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )

} )


describe( 'Jwt.sign() - DSA', () => {

	const passphrase = 'my-private-key-optional-passphrase'
	const keypair = crypto.generateKeyPairSync( 'dsa', {
		modulusLength		: 2048,
		divisorLength		: 256,
		publicKeyEncoding	: { type: 'spki', format: 'pem' },
		privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' }
	} )

	it( 'signs a token with DS1', () => {
		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'DS1' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )


	it( 'signs a token with DS256', () => {
		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'DS256' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )


	it( 'signs a token with DS384', () => {
		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'DS384' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )


	it( 'signs a token with DS512', () => {
		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'DS512' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )

} )


describe( 'Jwt.sign() - EcDSA', () => {

	const passphrase = 'my-private-key-optional-passphrase'

	it( 'signs a token with ES256', () => {
		const keypair = crypto.generateKeyPairSync( 'ec', {
			namedCurve			: 'secp256k1',
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'ES256' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )


	it( 'signs a token with ES384', () => {
		const keypair = crypto.generateKeyPairSync( 'ec', {
			namedCurve			: 'secp384r1',
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'ES384' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )


	it( 'signs a token with ES512', () => {
		const keypair = crypto.generateKeyPairSync( 'ec', {
			namedCurve			: 'secp521r1',
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'ES512' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )

} )


describe( 'Jwt.sign() - EdDSA', () => {

	const passphrase = 'my-private-key-optional-passphrase'

	it( 'signs a token with ed448', () => {
		const keypair = crypto.generateKeyPairSync( 'ed448', {
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' }
		} )

		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'EdDSA' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )


	it( 'signs a token with ed25519', () => {
		const keypair = crypto.generateKeyPairSync( 'ed25519', {
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' }
		} )

		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'EdDSA' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )

} )


describe( 'Jwt.sign() - RSA', () => {

	const bytes			= 256
	const passphrase	= 'my-private-key-optional-passphrase'
	const keypair		= crypto.generateKeyPairSync( 'rsa', {
		modulusLength		: bytes * 8,
		publicKeyEncoding	: { type: 'spki', format: 'pem' },
		privateKeyEncoding	: { type: 'pkcs1', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
	} )


	it( 'signs a token with RS1', () => {
		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'RS1' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )


	it( 'signs a token with RS256', () => {
		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'RS256' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )


	it( 'signs a token with RS384', () => {
		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'RS384' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )


	it( 'signs a token with RS512', () => {
		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'RS512' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )

} )


describe( 'Jwt.sign() - RSASSA-PSS', () => {

	const bytes			= 256
	const passphrase	= 'my-private-key-optional-passphrase'


	it( 'signs a token with PS256', () => {

		const hash = 'SHA-256'
		/** RSASSA-PSS using `hash` and MGF1 with `hash` */
		const keypair = crypto.generateKeyPairSync( 'rsa-pss', {
			modulusLength		: bytes * 8,
			hashAlgorithm		: hash,
			mgf1HashAlgorithm	: hash,
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'PS256' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )


	it( 'signs a token with PS384', () => {

		const hash = 'SHA-384'
		/** RSASSA-PSS using `hash` and MGF1 with `hash` */
		const keypair = crypto.generateKeyPairSync( 'rsa-pss', {
			modulusLength		: bytes * 8,
			hashAlgorithm		: hash,
			mgf1HashAlgorithm	: hash,
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'PS384' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )


	it( 'signs a token with PS512', () => {

		const hash = 'SHA-512'
		/** RSASSA-PSS using `hash` and MGF1 with `hash` */
		const keypair = crypto.generateKeyPairSync( 'rsa-pss', {
			modulusLength		: bytes * 8,
			hashAlgorithm		: hash,
			mgf1HashAlgorithm	: hash,
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const jwt = new Jwt( {
			data	: 'Data to be signed into the token.',
			header	: { alg: 'PS512' },
			key		: {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			},
		} )

		expect( jwt.sign() ).toBeTruthy()
	} )

} )