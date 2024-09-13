const crypto = require("crypto")
const express = require("express")
const app = express()
const redis = require("../scripts/redis")
const ecdsaKeyPair = require("../scripts/keypair")
require("dotenv").config()

const SHA256 = require("crypto-js/sha256")

// Import elliptic library
const elliptic = require("elliptic")
const ecdsa = new elliptic.ec("secp256k1")

app.use(express.json()) // Add this line to parse JSON bodies

app.post("/sign", async (req, res) => {
  try {
    const { data } = req.body
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

    // Create hash of the data
    const hash = crypto.createHash("sha256").update(data).digest("hex")

    // Sign the hash
    const key = ecdsa.keyFromPrivate(privateKey, "hex")
    const signature = key.sign(hash)
    const derSignature = signature.toDER("hex")

    // Respond with the signature and public key
    res.json({ signature: SHA256(derSignature).toString(), publicKey })
  } catch (error) {
    console.error("Error during signing:", error)
    res.status(500).json({ error: "Failed to sign data" })
  }
})

app.post("/verify", (req, res) => {
  try {
    const { signature, data, publicKey } = req.body

    if (!signature || !data || !publicKey) {
      return res
        .status(400)
        .json({ error: "Missing signature, data, or publicKey" })
    }

    // Create hash of the data
    const hash = crypto.createHash("sha256").update(data).digest("hex")

    // Get key from public key
    const key = ecdsa.keyFromPublic(publicKey, "hex")

    // Verify the signature
    const isValid = key.verify(hash, signature)

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
