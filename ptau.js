const fs = require("fs")
const snarkjs = require("snarkjs")
const { buildBn128 } = require("ffjavascript")

const power = parseInt(process.argv[2])

async function run() {
  const curve = await buildBn128()

  const tempPtauName = "temp.ptau"
  const ptauName = "powersOfTau" + power + "_0001.ptau";

  await snarkjs.powersOfTau.newAccumulator(curve, power, tempPtauName, console)

  await snarkjs.powersOfTau.contribute(tempPtauName, ptauName, 'space', (Math.random() * 1e60).toFixed(0), console)

  fs.unlinkSync(tempPtauName)
}

run().then(() => {
  process.exit(0)
})