import crypto from 'crypto'
import { Jwt } from '@/index'
import { Exception } from '@alessiofrittoli/exception'
import { ErrorCode } from '@/error'
import { Base64 } from '@alessiofrittoli/crypto-encoder'

const secretKey	= crypto.createSecretKey( Buffer.from( 'mysecretkey' ) )
const basicJwt	= (
	new Jwt( {
		data	: 'payload',
		key		: 'secretKey',
	} ).sign()
)

describe( 'Jwt', () => {

	it( 'validates the JWT Payload of the given token', () => {

		expect( () => (
			new Jwt( {
				token: basicJwt.split( '.' ).at( 0 )!,
			} )
		) ).toThrow( 'Invalid JWT Payload.' )

	} )
	

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
	
	
		it( 'creates a token with no signature', () => {
			const jwt = new Jwt( {
				data	: 'Data to be signed into the token.',
				header	: { alg: 'none' },
			} )
			
			const token = jwt.sign()
			const parts = token.split( '.' )
			
			expect( parts.length ).toBe( 2 )
		} )
	
	
		it( 'throws a new Exception if no payload has been provided', () => {
			// @ts-expect-error negative testing
			const jwt = new Jwt( {
				name	: 'access_token',
				header	: { alg: 'none' },
			} )
			
			try {
				jwt.sign()
			} catch ( error ) {
				expect( error ).toBeInstanceOf( Exception )
				if ( Exception.isException( error ) ) {
					expect( error.message ).toBe( 'No access_token payload provided.' )
					expect( error.code ).toBe( ErrorCode.Exception.EMPTY_VALUE )
				}
			}
	
		} )
	
	
		it( 'throws a new Exception if not Private Key has been provided', () => {
			const jwt = new Jwt( {
				data	: 'payload',
				name	: 'access_token',
				header	: { alg: 'HS256' },
			} )
			
			try {
				jwt.sign()
			} catch ( error ) {
				expect( error ).toBeInstanceOf( Exception )
				if ( Exception.isException( error ) ) {
					expect( error.message ).toBe( 'No private key provided for the access_token sign creation.' )
					expect( error.code ).toBe( ErrorCode.Signature.NO_PRIVATEKEY )
				}
			}
	
		} )
		
		
		it( 'throws a new Exception if Private Key cannot be used within the provided algortihm', () => {
			const jwt = new Jwt( {
				data	: 'payload',
				name	: 'access_token',
				key		: secretKey,
				header	: { alg: 'RS256' },
			} )
			
			try {
				jwt.sign()
			} catch ( error ) {
				expect( error ).toBeInstanceOf( Exception )
				if ( Exception.isException( error ) ) {
					expect( error.message ).toBe( 'An error occured while creating the signature.' )
					expect( error.code ).toBe( ErrorCode.Exception.UNKNOWN )
					expect( error.cause ).not.toBeNull()
				}
			}
	
		} )


		it( 'throws a new unkown Exception if caught error is not an Exception', () => {
			const jwt = new Jwt( {
				data	: 'payload',
				name	: 'access_token',
				key		: secretKey,
			} )

			// @ts-expect-error negative testing
			jwt.header = undefined

			expect( () => jwt.sign() ).toThrow( 'Unknown error while signing access_token.' )
			
		} )
	
	
		describe( 'HMAC', () => {
		
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
		
		
		describe( 'DSA', () => {
		
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
		
		
		describe( 'EcDSA', () => {
		
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
		
		
		describe( 'EdDSA', () => {
		
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
		
		
		describe( 'RSA', () => {
		
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
		
		
		describe( 'RSASSA-PSS', () => {
		
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
	
	} )
	
	
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


			const jwt2 = new Jwt( {
				token	: token,
				key		: secretKey,
				iss		: 'unexpected-issuer.it',
			} )
	
			expect( jwt.verify() ).toBe( true )
			expect( () => jwt2.verify() ).toThrow( 'Unknown JWT Issuer.' )
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
			
			const jwt2 = new Jwt( {
				token	: token,
				key		: secretKey,
				jti		: 'b2410r97-7d03-4502-9722-2b75d1bdc0ff',
			} )
	
			expect( jwt.verify() ).toBe( true )
			expect( () => jwt2.verify() ).toThrow( 'The given JWT ID is invalid.' )
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
			
			const jwt2 = new Jwt( {
				token	: token,
				key		: secretKey,
				aud		: [ 'example.com' ],
			} )
			

			const token2 = new Jwt( {
				data: 'Data to be signed into the token.',
				key	: secretKey,
				iss	: 'issuer-not-in-intended-audience.it',
				aud	: [ requestOrigin ],
			} ).sign()

			const jwt3 = new Jwt( {
				token	: token2,
				key		: secretKey,
				iss		: 'issuer-not-in-intended-audience.it',
			} )
	
			expect( jwt.verify() ).toBe( true )
			expect( () => jwt2.verify() ).toThrow( 'The given JWT is intended for a different audience.' )
			expect( () => jwt3.verify() ).toThrow( 'The given JWT is intended for a different audience.' )
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
	
	
		it( 'throws a new Exception if no token has been provided', () => {
			// @ts-expect-error negative testing
			const jwt = new Jwt( {
				name	: 'access_token',
				header	: { alg: 'none' },
			} )
	
			try {
				jwt.verify()
			} catch ( error ) {
				expect( error ).toBeInstanceOf( Exception )
				if ( Exception.isException( error ) ) {
					expect( error.message ).toBe( 'No access_token value to verify has been provided.' )
					expect( error.code ).toBe( ErrorCode.Exception.EMPTY_VALUE )
				}
			}
	
		} )
	
	
		it( 'throws a new Exception if a wrong formatted token header has been provided', () => {
			
			try {
				new Jwt( {
					name	: 'access_token',
					token	: 'invalid',
					header	: { alg: 'none' },
				} )
			} catch ( error ) {
				expect( error ).toBeInstanceOf( Exception )
				if ( Exception.isException( error ) ) {
					expect( error.message ).toBe( 'Invalid access_token JOSE Header.' )
					expect( error.code ).toBe( ErrorCode.Jwt.WRONG_HEADER )
				}
			}
	
		} )


		it( 'throws a new Exception if a wrong formatted token payload has been provided', () => {
			
			try {
				new Jwt( {
					name	: 'access_token',
					token	: [ Base64.encode( JSON.stringify( {} ) ), 'invalidpayload' ].join( '.' ),
					header	: { alg: 'none' },
				} )
			} catch ( error ) {
				expect( error ).toBeInstanceOf( Exception )
				if ( Exception.isException( error ) ) {
					expect( error.message ).toBe( 'Invalid access_token Payload.' )
					expect( error.code ).toBe( ErrorCode.Jwt.WRONG_JWS )
				}
			}
	
		} )


		it( 'throws a new Exception if a wrong formatted token is provided after initialization', () => {

			const jwt = new Jwt( {
				token	: basicJwt,
				key		: secretKey,
			} )

			// update the token value so we don't get an error in `Jwt.constructor`.
			jwt.token = basicJwt.split( '.' ).at( 0 )

			expect( () => jwt.verify() )
				.toThrow( 'Invalid JWT token format provided. It should be composed by 2 parts at least.' )
			
		} )


		it( 'throws a new Exception if verifying a token with an unexpected signature', () => {

			const token = new Jwt( {
				data	: 'payload',
				key		: secretKey,
				header	: { alg: 'none' },
			} ).sign()
			
			const signedToken = new Jwt( {
				data	: 'payload',
				key		: secretKey,
			} ).sign()

			const alteredToken = token + `.${ signedToken.split( '.' ).at( -1 ) }`

			const jwt = new Jwt( {
				token	: alteredToken,
				key		: secretKey,
				header	: { alg: 'none' },
			} )

			expect( () => jwt.verify() ).toThrow( 'Unexpected signature provided for the JWT.' )

		} )


		it( 'throws a new Exception if no signature is provided', () => {

			const token = new Jwt( {
				data	: 'payload',
				key		: secretKey,
			} ).sign()

			const jwtParts = token.split( '.' )
			jwtParts.pop()

			const alteredToken = jwtParts.join( '.' )

			const jwt = new Jwt( {
				token	: alteredToken,
				key		: secretKey,
			} )

			expect( () => jwt.verify() ).toThrow( 'No signature provided for the JWT.' )

		} )
		
		
		it( 'throws a new Exception if no public key is provided', () => {

			const token = new Jwt( {
				data	: 'payload',
				key		: secretKey,
			} ).sign()

			const jwt = new Jwt( {
				token: token,
			} )

			expect( () => jwt.verify() ).toThrow( 'No public key provided for the JWT sign verification.' )

		} )
		
		
		it( 'throws a new Exception if if the signature is not valid', () => {

			const token = new Jwt( {
				data	: 'payload',
				key		: secretKey,
			} ).sign()

			const jwtParts = token.split( '.' )
			jwtParts.pop()
			jwtParts.push( 'invalid-signature' )

			const alteredToken = jwtParts.join( '.' )

			const jwt = new Jwt( {
				token	: alteredToken,
				key		: secretKey,
			} )

			expect( () => jwt.verify() ).toThrow( 'Invalid signature.' )

		} )
		
		
		describe( 'HMAC', () => {
		
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
		
		
		describe( 'DSA', () => {
		
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
		
		
		describe( 'EcDSA', () => {
		
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
		
		
		describe( 'EdDSA', () => {
		
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
		
		
		describe( 'RSA', () => {
		
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
		
		
		describe( 'RSASSA-PSS', () => {
		
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
	
	} )


	describe( 'Jwt.verifyHeader()', () => {

		it( 'throws a new Exception if no `header` has been provided', () => {

			const jwt = new Jwt( {
				token	: basicJwt,
				key		: secretKey,
			} )

			expect( () => jwt[ 'verifyHeader' ]() )
				.toThrow( 'No JWT JOSE Header has been provided.' )

		} )


		it( 'throws a new Exception if an unexpected `algorith` is found', () => {

			const jwt = new Jwt( {
				token	: basicJwt,
				key		: secretKey,
				header	: { alg: 'DS1' }, // set a different algorithm used by `basicJwt` (HS256).
			} )

			expect( () => jwt.verify() )
				.toThrow( 'The JWT JOSE Header algorithm is not the expected algorithm.' )

		} )


		it( 'throws a new Exception if an unexpected `kid` is found', () => {

			const jwt = new Jwt( {
				token	: basicJwt,
				key		: secretKey,
				header	: { kid: 'key_id' },
			} )

			expect( () => jwt.verify() )
				.toThrow( 'The JWT JOSE Header `kid` is not the expected `kid`.' )

		} )
		
		
		it( 'throws a new Exception if caught error in not an Exception', () => {

			const jwt = new Jwt( {
				token	: basicJwt,
				key		: secretKey,
			} )

			expect( () => jwt[ 'verifyHeader' ]( Base64.encode( 'wrong json string' ) ) )
				.toThrow( 'Invalid JWT JOSE Header.' )

		} )

	} )
	
	
	describe( 'Jwt.toJSON()', () => {
	
		it( 'returns the signed token with the provided `data`', () => {
			const jwt = new Jwt( {
				key		: secretKey,
				data	: 'payload'
			} )
	
			expect( jwt.toJSON() ).toBe( jwt.sign() )
		} )
	
	
		it( 'returns the given token if provided', () => {
			const token = new Jwt( {
				key		: secretKey,
				data	: 'payload'
			} ).sign()
	
			const jwt = new Jwt( { token } )
	
			expect( jwt.toJSON() ).toBe( token )
		} )
		
	} )

} )