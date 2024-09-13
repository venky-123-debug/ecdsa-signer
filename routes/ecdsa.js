const crypto = require("crypto")
const express = require("express")
const app = express()
const redis = require("../scripts/redis")
const ecdsaKeyPair = require("../scripts/keypair")
require("dotenv").config()

// Import elliptic library
const elliptic = require("elliptic")
const ecdsa = new elliptic.ec("secp256k1")

app.use(express.json()) // Add this line to parse JSON bodies

app.post("/sign", async (req, res) => {
  try {
    let { data } = req.body
    if (!data) {
      return res.status(400).json({ error: "No data provided" })
    }

    // Retrieve or generate key pair
    let thisEcdsa = await redis.get("ecdsa")
    let keyPair = JSON.parse(thisEcdsa)
    let privateKey, publicKey

    if (keyPair) {
      privateKey = keyPair.privateKey
      publicKey = keyPair.publicKey
    } else {
      keyPair = await ecdsaKeyPair.ecdsakeygen()
      await redis.setex(
        "ecdsa",
        process.env.REDIS_DATA_EXPIRY,
        JSON.stringify(keyPair)
      )
      privateKey = keyPair.privateKey
      publicKey = keyPair.publicKey
    }
    let hash = crypto.createHash("sha256").update(data).digest()

    // Sign the hash
    let key = ecdsa.keyFromPrivate(privateKey, "hex")
    let signature = key.sign(hash)

    // Get the DER-encoded signature and convert to hex
    let derSignature = signature.toDER("hex")

    // Respond with the signature and public key
    res.json({ signature: derSignature, publicKey })
  } catch (error) {
    console.error("Error during signing:", error)
    res.status(500).json({ error: "Failed to sign data" })
  }
})

app.get("/verify", (req, res) => {
  try {
    let { signature, data, publicKey } = req.query

    if (!signature || !data || !publicKey) {
      return res
        .status(400)
        .json({ error: "Missing signature, data, or publicKey" })
    }

    // Create hash of the data
    let hash = crypto.createHash("sha256").update(data).digest()

    // Get key from public key
    let key = ecdsa.keyFromPublic(publicKey, "hex")
    console.log({ key })
    // Verify the signature
    let isValid = key.verify(hash, signature)
    console.log({ isValid })
    if (isValid) {
      res.json({ verified: true })
    } else {
      res.status(400).json({ verified: false, error: "Invalid signature" })
    }
  } catch (error) {
    console.error("Error during verification:", error)
    res.status(500).json({ error: "Verification failed" })
  }
})

module.exports = app
