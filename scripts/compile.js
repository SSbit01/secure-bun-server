import { generateLicenseFile } from "generate-license-file"
import generateLicenseFileConfig from "../.generatelicensefile.json"


const output = "./dist"

console.log("Compiling...")

await Promise.all([
  generateLicenseFile("./package.json", output + "/LICENSES.txt", generateLicenseFileConfig),
  Bun.build({
    bytecode: true,
    compile: {
      outfile: "index"
    },
    define: {
      "process.env.NODE_ENV": '"production"'
    },
    entrypoints: ["./src/index.js"],
    minify: true,
    outdir: output,
    target: "bun"
  })
])

console.log("Compilation complete!")