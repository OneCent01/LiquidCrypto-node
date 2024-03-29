const crypto = require('crypto')

const ab2str =  buf => String.fromCharCode.apply(null, new Uint8Array(buf))

const str2ab = str => {
  const buf = new ArrayBuffer(str.length)
    bufView = new Uint8Array(buf)
  let i = str.length
  while(i--) {
    bufView[i] = str.charCodeAt(i)
  }
  return buf
}

// const toBuffer =  ab => {
//     const buf = Buffer.alloc(ab.byteLength)
//     const view = new Uint8Array(ab)
//     for (let i = 0; i < buf.length; ++i) {
//         buf[i] = view[i]
//     }
//     return buf
// }

const LiquidCrypto = (options={}) => {
	const { keypair, log } = options
	const liqLog = (...args) => log ? console.log(...args) : null
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
		liqLog('Encrypt data: ', data)
		const iv = crypto.randomBytes(ivLength).toString('base64').slice(0, ivLength)
		liqLog('generated iv: ', iv)
		const cipher = crypto.createCipheriv(
			'aes-256-gcm',
			key,
			iv
		)

		const encrypted = `${cipher.update(data).toString('base64')}${cipher.final().toString('base64')}`
		liqLog('Encrypted: ', encrypted)
		const ivEncrypted = `${iv}${encrypted}`
		liqLog('iv + encrypted: ', ivEncrypted)
		return ivEncrypted
	}

	const decrypt = (data, key) => {
		liqLog('Decrypt data: ', data)
		const iv = data.slice(0, ivLength)
		liqLog('incoming iv: ', iv)
		const encryptedData = data.slice(ivLength)
		liqLog('incoming data: ', encryptedData)
		const decipher = crypto.createDecipheriv(
			'aes-256-gcm',
			str2ab(key),
			str2ab(iv)
		)

		const decrypted = decipher.update(encryptedData, 'base64', 'utf8')
		liqLog('decrypted: ', decrypted)
		return decrypted
	}	

	return {
		publicKey: liquidState.keypair.getPublicKey(),
		deriveKey,
		encrypt,
		decrypt
	}
}

module.exports = { LiquidCrypto }

