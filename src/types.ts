import type Sign from '@alessiofrittoli/crypto-signature/types'

namespace JsonWebToken
{
	/**
	 * JWS Signature algorithm parameter.
	 * 
	 * @link https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
	 */
	export type Algorithm = Sign.AlgorithmJwkName | (
		| 'none' // No digital signature or MAC performed
	)

	
	/**
	 * JOSE Header.
	 *
	 * The JOSE (JSON Object Signing and Encryption) Header contains the parameters
	 * describing the cryptographic operations and parameters employed.
	 * The JOSE Header is comprised of a set of Header Parameters that
	 * typically consist of a name/value pair: the hashing algorithm being used (e.g., HMAC SHA256 or RSA) and the type of the JWT.
	 */
	export interface Header
	{
		/** Message authentication code algorithm - The issuer can freely set an algorithm to verify the signature on the token. However, some supported algorithms are [insecure](https://www.chosenplaintext.ca/2015/03/31/jwt-algorithm-confusion.html). */
		alg: JsonWebToken.Algorithm
		/** Token type - If present, it must be set to a registered [IANA Media Type](https://www.iana.org/assignments/media-types/media-types.xhtml). */
		typ: 'JWT'
		/** Content type - If nested signing or encryption is employed, it is recommended to set this to JWT; otherwise, omit this field. */
		cty?: string
		/** Key ID - A hint indicating which key the client used to generate the token signature. The server will match this value to a key on file in order to verify that the signature is valid and the token is authentic. */
		kid?: string
		/** Critical - A list of headers that must be understood by the server in order to accept the token as valid. */
		crit?: Array<string | Exclude<keyof Header, 'crit'>>
		/** x.509 Certificate Chain - A certificate chain in RFC4945 format corresponding to the private key used to generate the token signature. The server will use this information to verify that the signature is valid and the token is authentic. */
		x5c?: string | string[]
		/** x.509 Certificate Chain URL - A URL where the server can retrieve a certificate chain corresponding to the private key used to generate the token signature. The server will retrieve and use this information to verify that the signature is authentic. */
		x5u?: string | string[]
		x5t?: string
		jku?: string
		'x5t#S256'?: string
	}


	/**
	 * JWS payload.
	 * The payload contains statements about the entity (typically, the user) and additional entity attributes, which are called claims.
	 */
	export type JwsPayload = {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		[ key: string ]: any
		/** Issued at - Identifies the time at which the JWT was issued. The value must be a NumericDate either an integer or decimal, representing seconds past unix epoch. */
		iat: number
		/**
		 * Issuer - Identifies principal that issued the JWT.
		 * It doesn't matter exactly what this string is (UUID, domain name, URL or something else) as long as the issuer and consumer of the JWT agree on valid values,
		 * and that the consumer validates the claim matches a known good value.
		 */
		iss?: string
		/** Subject - Identifies the subject of the JWT. */
		sub?: string
		/** Audience - Identifies the recipients that the JWT is intended for. Each principal intended to process the JWT must identify itself with a value in the audience claim. If the principal processing the claim does not identify itself with a value in the aud claim when this claim is present, then the JWT must be rejected. */
		aud?: string | string[]
		/** Not Before - Identifies the time on which the JWT will start to be accepted for processing. The value must be a NumericDate either an integer or decimal, representing seconds past unix epoch. */
		nbf?: number
		/** Expiration Time - Identifies the expiration time on and after which the JWT must not be accepted for processing. The value must be a NumericDate either an integer or decimal, representing seconds past unix epoch. */
		exp?: number
		/** JWT ID - Case-sensitive unique identifier of the token even among different issuers. */
		jti?: string
	}


	/**
	 * The actual JWS payload with additional data.
	 * 
	 */
	export type Payload<T> = T extends string | number | boolean | Array<unknown> ? { data: T } & JwsPayload : T & JwsPayload


	/**
	 * Accepted properties for the Jwt instance.
	 * 
	 */
	export type Props<T = unknown> = {
		/** The Token name. */
		name?: string
		/** The JOSE Header. */
		header?: Partial<Omit<JsonWebToken.Header, 'typ'>>
		/** The token issuing Date time value in milliseconds past unix epoch, a Date string or a Date instance on which the JWT it has been issued. */
		iat?: string | number | Date
		/** The token expiration Date time value in milliseconds past unix epoch, a Date string or a Date instance on and after which the JWT it's not accepted for processing. */
		exp?: string | number | Date
		/** The token Date time value in milliseconds past unix epoch, a Date string or a Date instance on which the JWT will start to be accepted for processing. */
		nbf?: string | number | Date
	} & ( {
		/** The token value. */
		token: string
		data?: never
		/** The token secret key used for HMAC or the PEM public key for RSA, ECDSA and RSASSA-PSS sign verification algorithms. */
		key?: Sign.PublicKey
	} | {
		/** The Payload data to sign into the token. Could be anything. */
		data: T
		token?: never
		/** The token secret key used for HMAC or the PEM private key for RSA, ECDSA and RSASSA-PSS signing algorithms. */
		key?: Sign.PrivateKey
	} ) & Pick<JsonWebToken.JwsPayload, 'jti' | 'iss' | 'sub' | 'aud'>
}

export default JsonWebToken