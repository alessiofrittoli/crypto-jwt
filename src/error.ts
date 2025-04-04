import { ErrorCode as SignatureErrorCode } from '@alessiofrittoli/crypto-signature/error'

enum Jwt
{
	WRONG_FORMAT		= 'ERR:WRONGFORMAT',
	NO_HEADER			= 'ERR:NOHEADER',
	WRONG_HEADER		= 'ERR:WRONGJOSEHEADERFORMAT',
	WRONG_ALGO			= 'ERR:WRONGALGO',
	WRONG_KID			= 'ERR:WRONGKID',
	WRONG_JWS			= 'ERR:WRONGJWSFORMAT',
	UNEXPECTED_ISSUER	= 'ERR:UNEXPECTEDISSUER',
	UNEXPECTED_AUDIENCE	= 'ERR:UNEXPECTEDAUDIENCE',
	UNEXPECTED_JTI		= 'ERR:UNEXPECTEDJTI',
	UNEXPECTED_SIGN		= 'ERR:UNEXPECTEDSIGN',
}

export const ErrorCode	= { ...SignatureErrorCode, Jwt }
export type ErrorCode	= MergedEnumValue<typeof ErrorCode>