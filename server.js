const express = require("express")
const app = express()

const bodyParser = require("body-parser")
require("dotenv").config()

app.use(bodyParser.json())
const routes = require("./routes/index")
app.use("/", routes)
startup()
async function startup() {
  try {
    app.listen(process.env.PORT, () => {
      console.log(`Server is running on port ${process.env.PORT}`)
    })
  } catch (error) {
    console.error("error in connecting port")
  }
}
