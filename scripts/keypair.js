const { ec } = require("elliptic")

module.exports.ecdsakeygen = () => {
  return new Promise((resolve, reject) => {
    try {
      const ecdsa = new ec("secp256k1")

      // Generate a new key pair
      const keyPair = ecdsa.genKeyPair()

      // Get the private and public keys
      const privateKey = keyPair.getPrivate("hex")
      const publicKey = keyPair.getPublic("hex")

      console.log("Private Key:", privateKey)
      console.log("Public Key:", publicKey)

      resolve({ privateKey, publicKey })
    } catch (error) {
      reject(error)
    }
  })
}
