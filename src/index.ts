import { Base64 } from '@alessiofrittoli/crypto-encoder'
import Signature from '@alessiofrittoli/crypto-signature'
import type Sign from '@alessiofrittoli/crypto-signature/types'
import Exception from '@alessiofrittoli/exception'

import type JsonWebToken from './types'
import { ErrorCode } from './error'


/**
 * JsonWebToken Class [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) standard.
 * 
 * @link [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)
 * @link [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
 */
class Jwt<T = unknown> implements Omit<JsonWebToken.Props<T>, 'algorithm' | 'data'>
{
	/**
	 * The JOSE (JSON Object Signing and Encryption) Header contains the parameters
	 * describing the cryptographic operations and parameters employed.
	 * The JOSE Header is comprised of a set of Header Parameters that
	 * typically consist of a name/value pair: the hashing algorithm being used (e.g., HMAC SHA256 or RSA) and the type of the JWT.
	 */
	header: JsonWebToken.Header
	/** The JWS payload. */
	payload: JsonWebToken.Payload<T>
	/** The JSON Web Signature. */
	signature: Buffer | null

	jti
	iss
	sub
	aud

	name
	token
	key

	iat
	exp
	nbf
	/** Whether the token has been verified or not. */
	isVerified: boolean | null
	
	
	private data: JsonWebToken.Props<T>[ 'data' ]
	/** The JWK algorithm name to use while signing or the expected JWK algorithm name when verifying. */
	private algorithm: JsonWebToken.Algorithm
	private expectedHeader: JsonWebToken.Header

	static defaultAlgorithm: JsonWebToken.Algorithm = 'HS256'

	constructor( props: JsonWebToken.Props<T> )
	{
		this.token		= props.token
		this.name		= props.name || 'JWT'
		this.key		= props.key
		this.data		= props.data
		this.algorithm	= props.header?.alg || 'HS256'

		this.jti	= props.jti
		this.iss	= props.iss
		this.sub	= props.sub
		this.aud	= props.aud?.toString().split( ',' )
		this.iat	= props.iat ? new Date( props.iat ) : undefined
		this.exp	= props.exp ? new Date( props.exp ) : undefined
		this.nbf	= props.nbf ? new Date( props.nbf ) : undefined

		this.header		= this.parseHeader( props.header )
		this.payload	= this.parsePayload()
		this.signature	= this.parseSignature()
		this.isVerified	= null
	}


	/**
	 * Syncronously sign the JSON Web Token.
	 *
	 * @returns	The signed JSON Web Token string.
	 */
	sign()
	{
		if ( ! this.payload ) {
			throw new Exception( `No ${ this.name } payload provided.`, {
				code: ErrorCode.EMPTY_VALUE,
			} )
		}
		try {
			const header	= Base64.encode( JSON.stringify( this.header ), true )
			const payload	= Base64.encode( JSON.stringify( this.payload ), true )
			const signature	= this.createSignature( header, payload )
			this.token		= [ header, payload, signature ].filter( Boolean ).join( '.' )

			return this.token
		} catch ( error ) {
			if ( Exception.isException( error ) ) {
				throw error
			}
			throw new Exception( `Unknown error while signing ${ this.name }.`, {
				code	: ErrorCode.UNKNOWN,
				cause	: error,
			} )
		}
	}


	/**
	 * Syncronously verify a JSON Web Token.
	 *
	 * @returns The decoded Token Payload.
	 */
	verify()
	{
		if ( ! this.token ) {
			throw new Exception( `No ${ this.name } value to verify has been provided.`, {
				code: ErrorCode.EMPTY_VALUE,
			} )
		}

		const jwtParts	= this.token.split( '.' )

		if ( jwtParts.length < 2 ) {
			throw new Exception( `Invalid ${ this.name } token format provided. It should be composed by 2 parts at least.`, {
				code: ErrorCode.WRONG_FORMAT,
			} )
		}

		this.verifyHeader( jwtParts.at( 0 ) )
		this.verifySignature( jwtParts.at( 0 ) || '', jwtParts.at( 1 ) || '', jwtParts.at( 2 ) )
		this.verifyPayload()

		return true
	}


	/**
	 * Parse and verify a JOSE Header.
	 * 
	 * @param header The base64url JOSE Header string.
	 * 
	 * @todo verify header.crit
	 * 
	 * @returns The JOSE verified Header.
	 */
	private verifyHeader( header?: string )
	{
		if ( ! header ) {
			throw new Exception( `No ${ this.name } JOSE Header has been provided.`, {
				code: ErrorCode.NO_HEADER,
			} )
		}

		try {
			const parsed = JSON.parse<JsonWebToken.Header>( Base64.decode( header ).toString() )

			if ( parsed.alg !== this.expectedHeader.alg ) {
				throw new Exception( `The ${ this.name } JOSE Header algorithm is not the expected algorithm.`, {
					code: ErrorCode.WRONG_ALGO,
				} )
			}
			if ( parsed.kid !== this.expectedHeader.kid ) {
				throw new Exception( `The ${ this.name } JOSE Header \`kid\` is not the expected \`kid\`.`, {
					code: ErrorCode.WRONG_KID,
				} )
			}
			
			return parsed
		} catch ( err ) {
			if ( Exception.isException( err ) ) {
				throw err
			}
			throw new Exception( `Invalid ${ this.name } JOSE Header.`, {
				cause	: err,
				code	: ErrorCode.WRONG_HEADER,
			} )
		}
	}
	
	
	/**
	 * Verify JWS Payload.
	 * 
	 * @returns The JWS verified Payload.
	 */
	private verifyPayload()
	{
		const now = new Date()
		now.setMilliseconds( 0 )

		if ( this.payload.exp && this.payload.exp <= ( now.getTime() / 1000 ) ) {
			throw new Exception( `The ${ this.name } is expired and no longer accepted.`, {
				code: ErrorCode.EXPIRED,
			} )
		}
		
		if ( this.payload.nbf && this.payload.nbf >= ( now.getTime() / 1000 ) ) {
			throw new Exception( `The ${ this.name } is not yet in charge and it cannot be processed.`, {
				code: ErrorCode.TOO_EARLY,
			} )
		}


		if ( this.iss !== this.payload.iss ) {
			throw new Exception( `Unknown ${ this.name } Issuer.`, {
				code: ErrorCode.UNEXPECTED_ISSUER,
			} )
		}


		const audience = this.payload.aud?.toString().split( ',' )
		
		if (
			( this.iss && audience && ! audience.includes( this.iss ) ) ||
			( this.aud && this.aud.length > 0 && ( ! audience || audience.length <= 0 ) ) ||
			( this.aud && this.aud.length > 0 && ! audience?.some( n => this.aud?.includes( n ) ) )
		) {
			/**
			 * Server has defined an issuer principal but parsed payload doesn't contain that principal OR 
			 * Server has defined an audience but parsed payload not OR
			 * Server has defined an audience but parsed payload has defined a different audience.
			 */
			throw new Exception( `The given ${ this.name } is intended for a different audience.`, {
				code: ErrorCode.UNEXPECTED_AUDIENCE,
			} )
		}

		if ( this.jti !== this.payload.jti ) {
			throw new Exception( `The given ${ this.name } ID is invalid.`, {
				code: ErrorCode.UNEXPECTED_JTI,
			} )
		}


		return this.payload
	}


	/**
	 * Syncronously verify the JSON Web Token signature.
	 * 
	 * @param header	The base64url JOSE Header string.
	 * @param payload	The base64url JWS Payload string.
	 * @param signature	The base64url JWT signature string.
	 * 
	 * @returns	The signature if is valid, throws a new Exception otherwise.
	 */
	private verifySignature( header: string, payload: string, signature?: string )
	{
		if ( this.algorithm === 'none' && !! signature ) {
			throw new Exception( `Unexpected signature provided for the ${ this.name }.`, {
				code: ErrorCode.UNEXPECTED_SIGN,
			} )
		}
		
		if ( this.algorithm === 'none' ) {
			this.isVerified = true
			return this.isVerified
		}

		if ( ! signature ) {
			throw new Exception( `No signature provided for the ${ this.name }.`, {
				code: ErrorCode.NO_SIGN,
			} )
		}

		if ( ! this.key ) {
			throw new Exception( `No public key provided for the ${ this.name } sign verification.`, {
				code: ErrorCode.NO_PUBLICKEY,
			} )
		}

		try {

			this.isVerified = Signature.isValid(
				Base64.decode( signature ),
				[ header, payload ].join( '.' ),
				this.key as Sign.PublicKey,
				this.algorithm
			)
	
			return this.isVerified
		} catch ( err ) {

			this.isVerified = false
			
			throw new Exception( `Invalid ${ this.name } signature.`, {
				cause	: err,
				code	: ErrorCode.INVALID_SIGN,
			} )

		}
	}


	private parseHeader( header?: JsonWebToken.Props<T>[ 'header' ] ): JsonWebToken.Header
	{
		const jwtParts	= this.token?.split( '.' ) || []
		const jwtHeader	= jwtParts.at( 0 )

		header ||= {}
		const parsed: JsonWebToken.Header = {
			typ: 'JWT', ...header, alg: this.algorithm
		}
		this.expectedHeader = parsed
		if ( ! this.token || ! jwtHeader ) {
			return parsed
		}

		try {
			return JSON.parse<JsonWebToken.Header>( Base64.decode( jwtHeader ).toString() )
		} catch ( err ) {
			throw new Exception( `Invalid ${ this.name } JOSE Header.`, {
				cause	: err,
				code	: ErrorCode.WRONG_HEADER,
			} )
		}
	}


	private parsePayload()
	{
		if ( this.data != null ) {

			this.iat ||= new Date()
			this.iat.setMilliseconds( 0 )
			if ( this.exp ) this.exp.setMilliseconds( 0 )
			if ( this.nbf ) this.nbf.setMilliseconds( 0 )

			const flatten = typeof this.data === 'object' && ! Array.isArray( this.data )

			return {
				...( ! flatten ? { data: this.data } : this.data ),
				iat: this.dateToSec( this.iat ),
				exp: this.exp ? this.dateToSec( this.exp ) : undefined,
				nbf: this.nbf ? this.dateToSec( this.nbf ) : undefined,
				iss: this.iss,
				aud: this.aud,
				jti: this.jti,
				sub: this.sub,
			} as JsonWebToken.Payload<T>
		}

		if ( this.token ) {
			try {

				/** The token has been already created and need to be verified. */
				const jwtParts	= this.token.split( '.' )
				const payload	= JSON.parse<JsonWebToken.Payload<T>>( Base64.decode( jwtParts.at( 1 ) || '' ).toString() )

				if ( payload.iat ) {
					this.iat = new Date( payload.iat * 1000 )
				}
				if ( payload.exp ) {
					this.exp = new Date( payload.exp * 1000 )
				}
				if ( payload.nbf ) {
					this.nbf = new Date( payload.nbf * 1000 )
				}

				this.payload = payload

				return this.payload

			} catch ( err ) {
				throw new Exception( `Invalid ${ this.name } Payload.`, {
					cause	: err,
					code	: ErrorCode.WRONG_JWS,
				} )
			}
		}
		
		return this.payload
	}


	private parseSignature(): Buffer | null
	{
		if ( ! this.token ) return null

		const jwtParts	= this.token.split( '.' )
		const signature	= jwtParts.at( 2 )
		if ( ! signature ) return null

		return (
			! signature
				? null
				: Buffer.from( Base64.decode( signature ) )
		)
	}


	/**
	 * Syncronously create the JSON Web Token base64url encoded signature.
	 *
	 * @param header	The base64url JOSE Header string.
	 * @param payload	The base64url JWS Payload string.
	 * 
	 * @returns	The HMAC/RSASSA/RSASSA-PSS/ECDSA base64url encoded signature.
	 */
	private createSignature( header: string, payload: string )
	{
		if ( this.header.alg === 'none' ) return ''
		
		if ( ! this.key ) {
			throw new Exception( `No private key provided for the ${ this.name } sign creation.`, {
				code: ErrorCode.NO_PRIVATEKEY,
			} )
		}

		const data		= [ header, payload ].join( '.' )
		this.signature	= Signature.sign( data, this.key as Sign.PrivateKey, this.header.alg )
		
		return (
			Base64.encode( this.signature, true )
		)
	}


	private dateToSec( date: Date )
	{
		return date.getTime() / 1000
	}
}

export default Jwt