import server from "#src/server";

console.log(server.url.origin);
console.log("DEVELOPMENT:", server.development);

async function shutdown() {
  console.log("Stopping server gracefully...");
  await server.stop();
  console.log("Server successfully stopped.");
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
