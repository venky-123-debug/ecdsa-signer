const crypto = require("crypto")
const express = require("express")
const app = express()

const redis = require("../scripts/redis")
const ecdsaKeyPair = require("../scripts/keypair")
require("dotenv").config()

app.post("/sign", async (req, res) => {
  try {
    let data = req.body.data
    if (!data) {
      return res.status(400).json({ error: "No data provided" })
    }

    let thisEcdsa = await redis.get("ecdsa")
    let keyPair = JSON.parse(thisEcdsa)
    if (keyPair) {
      privateKey = keyPair.privateKey
    } else {
      let keyPair = await ecdsaKeyPair.ecdsakeygen()
      await redis.setex(
        "ecdsa",
        process.env.REDIS_DATA_EXPIRY,
        JSON.stringify(keyPair)
      )
    }
    // Create hash of the data
    let hash = crypto.createHash("sha256").update(data).digest("hex")

    // Sign the hash
    let key = ecdsa.keyFromPrivate(privateKey, "hex")
    let signature = key.sign(hash)
    let derSignature = signature.toDER("hex")

    res.json({ hash, signature: derSignature })
  } catch (error) {
    console.error("Error during signing:", error)
    res.status(500).json({ error: "Failed to sign data" })
  }
})

app.post("/verify", (req, res) => {
  try {
    const { pubkey, msg, signature } = req.body

    if (!pubkey || !msg || !signature) {
      return res
        .status(400)
        .json({ error: "Missing pubkey, msg, or signature" })
    }

    // Hash the message
    const hash = crypto.createHash("sha256").update(msg).digest("hex")

    // Get key from public key
    const key = ecdsa.keyFromPublic(pubkey, "hex")

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
