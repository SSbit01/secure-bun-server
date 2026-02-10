import OPTIONS from "#src/options"

const server = Bun.serve(OPTIONS)

console.log(server.url.origin)