const crypto = require('crypto')

const LiquidCrypto = (keypair) => {

	// private method for creating an asymmetric keypair object,
	// generating its keys, and returning a reference to the object
	const generateKeys = () => {
		const ecdh = crypto.createECDH('prime256v1')
		ecdh.generateKeys()
		return ecdh
	}

	// state used to track internal variables
	const liquidState = {
		// keypair associated with this crypto wrapper
		keypair: keypair || generateKeys()
	}

	// outputs a 32 byte (256 bits) buffer object
	const deriveKey = (publicKey) => (
		liquidState.keypair !== null 
			? liquidState.keypair.computeSecret(publicKey) 
			: 'ERROR: keys not yet generated'
	)

	const ivLength = 12
	const encrypt = (data, key) => {
		const iv = crypto.randomBytes(ivLength).toString('base64').slice(0, ivLength)
		console.log('iv: ', iv)
		console.log('iv len: ', iv.length)
		const cipher = crypto.createCipheriv(
			'aes-256-gcm',
			key,
			iv
		)

		return `${iv.toString('base64')}${cipher.update(data).toString('base64')}${cipher.final().toString('base64')}`
	}

	const decrypt = (data, key) => {
		const iv = data.slice(0, ivLength)
		console.log('d-iv: ', iv)
		const encryptedData = data.slice(ivLength)

		const decipher = crypto.createDecipheriv(
			'aes-256-gcm',
			key,
			iv
		)

		return decipher.update(encryptedData, 'base64', 'utf8')
	}	

	return {
		publicKey: liquidState.keypair.getPublicKey(),
		deriveKey,
		encrypt,
		decrypt
	}
}

module.exports = { LiquidCrypto }

