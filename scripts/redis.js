// Import the "ioredis" library
const Redis = require("ioredis")

// Set up the Redis options based on environment variables
let redisOptions = {}

if (process.env.REDIS_MODE == "sentinel") {
  redisOptions = {
    sentinels: [
      {
        host: process.env.REDIS_SENTINEL,
        port: process.env.REDIS_SENTINEL_PORT,
      },
    ],
    name: process.env.REDIS_HA_NAME,
  }

  // Check if a Redis password is provided
  if (process.env.REDIS_PASSWORD) {
    // Set the Redis sentinel password
    redisOptions.sentinelPassword = process.env.REDIS_PASSWORD
    // Set the Redis password
    redisOptions.password = process.env.REDIS_PASSWORD
  }
} else {
  redisOptions = {
    port: process.env.REDIS_PORT,
    host: process.env.REDIS_IP,
  }
  // Check if a Redis password is provided
  if (process.env.REDIS_PASSWORD) {
    // Set the Redis password
    redisOptions.password = process.env.REDIS_PASSWORD
  }
}

/**
 * Create a new Redis instance with the provided options
 * @type {import("ioredis").Redis}
 */
module.exports = new Redis(redisOptions)
