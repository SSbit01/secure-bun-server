import OPTIONS from "#src/options";

const server = Bun.serve(OPTIONS);

console.log(server.url.origin);

async function shutdown() {
  console.log("Stopping server gracefully...");
  await server.stop();
  console.log("Server successfully stopped.");
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
