// const SHA256 = require("crypto-js/sha256")
const express = require("express")
const app = express()

require("dotenv").config()

const ecdsa = require("./ecdsa")

app.use("/ecdsa/", ecdsa)

module.exports = app
