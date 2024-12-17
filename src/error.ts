import { ErrorCode as SignatureErrorCode } from '@alessiofrittoli/crypto-signature/error'

enum JwtErrorCode
{
	WRONG_FORMAT		= 'ERR:WRONGFORMAT',
	NO_HEADER			= 'ERR:NOHEADER',
	WRONG_HEADER		= 'ERR:WRONGJOSEHEADERFORMAT',
	WRONG_ALGO			= 'ERR:WRONGALGO',
	WRONG_KID			= 'ERR:WRONGKID',
	WRONG_JWS			= 'ERR:WRONGJWSFORMAT',
	EXPIRED				= 'ERR:EXPIRED',
	TOO_EARLY			= 'ERR:TOOEARLY',
	UNEXPECTED_ISSUER	= 'ERR:UNEXPECTEDISSUER',
	UNEXPECTED_AUDIENCE	= 'ERR:UNEXPECTEDAUDIENCE',
	UNEXPECTED_JTI		= 'ERR:UNEXPECTEDJTI',
	UNEXPECTED_SIGN		= 'ERR:UNEXPECTEDSIGN',
}


export const ErrorCode = { ...SignatureErrorCode, ...JwtErrorCode }
export type ErrorCode = typeof ErrorCode