import { generateLicenseFile } from "generate-license-file"
import generateLicenseFileConfig from "../.generatelicensefile.json"


const output = "./dist"

console.log("Building...")

await Promise.all([
  generateLicenseFile("./package.json", output + "/LICENSES.txt", generateLicenseFileConfig),
  Bun.build({
    bytecode: true,
    define: {
      "process.env.NODE_ENV": '"production"'
    },
    entrypoints: ["./src/index.js"],
    minify: true,
    outdir: output,
    target: "bun"
  })
])

console.log("Build complete!")