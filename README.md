# Secure Bun Server

Template with passwordless authentication via email, KMS, and a MariaDB/MySQL database configured in Bun.
Perfect for building performant and secure platform servers.

> [!CAUTION]
>
> This server implements several security best practices, but it is not a complete security solution on its own.
> Additional measures such as DDoS protection, rate limiting, and request throttling are necessary for a production environment.
> It is recommended to configure these externally via a reverse proxy.
>
> If you discover a vulnerability, please read the [Security Policy](./SECURITY.md).

> [!IMPORTANT]
>
> This project is still under development. Many tests are still missing.

## Features

### Secure by Design

Generates cryptographically secure OTPs and encrypts session data using envelope encryption with
[AES-256-KW](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/wrapKey#AES-256-KW) (KEK)
and [AES-256-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) (DEK),
which is extremely fast on modern CPUs because they have dedicated hardware acceleration
([AES-NI](https://en.wikipedia.org/wiki/AES_instruction_set)),
in addition to being quantum-resistant.

### State Aware

Prevents replay attacks in authentication by using single use verification keys, while remaining lightweight.

### Multi-Credential Login Sessions

Store several OTP tokens per login session, each bound to a different credential.
Users can move between credentials without restarting the flow,
and the login session encrypted cookie enforces a strict cap so tokens stay lightweight.

## OTP Architecture

This server uses a hybrid design that provides even more security than a stateful design.
The server only stores random IDs, so it cannot know which credentials are currently being verified,
providing enhanced privacy and security without the overhead of a traditional storage system.

1. When an OTP is created, its metadata (credential, expiry, attempts...) is compressed and appended to an encrypted list of tokens
(one entry per credential) using envelope encryption with AES-256-KW (KEK) and AES-256-GCM (DEK).
The encrypted list is sent to the client in a secure, `HttpOnly` cookie.
2. A random ID linked to the list is generated and stored on the server.
3. When the client attempts to verify an OTP token, it sends back the encrypted list.
The server selects the current credential's token, and after each verification attempt updates its ID.
4. The encrypted cookie stores at most `OTP_MAX_CREDENTIALS` entries (specified in [`src/lib/otp/custom.js`](src/lib/otp/custom.js)), so users can switch between
multiple credentials without restarting the flow while keeping the session footprint small.

This process ensures that each encrypted token can only be used for verification once, effectively preventing replay attacks.
By default, the KMS stores key encryption keys (KEKs) in memory, but it can be customized in [`src/lib/kms.js`](/src/lib/kms.js)
to use a persistent store like Redis or KV storage for serverless environments or distributed systems.

## Getting Started

### 1. Installation

Clone the repository and install dependencies using your preferred package manager.

```sh
bun install
```

### 2. Configuration

Create a `.env` file in the root of the project. For production, set `NODE_ENV` to `"production"` to enable secure cookies and
specify your frontend's origin with `APP_ORIGIN` and your MariaDB/MySQL database URL with `DATABASE_URL`.

```env
# .env
NODE_ENV="production"
APP_ORIGIN="https://my-web-app.example.com"
DATABASE_URL="mariadb://root@localhost:3306/platform"
PORT=3000
```

See [`sample.env`](/sample.env).

### 3. Running the Server

You can run the server in development mode.

```sh
bun run dev
```

## Testing

The test suite is written with Bun's built-in test runner. Use `bun run test` to run the tests.

## License

This project is [MIT licensed](/LICENSE).

The default NPM build scripts automatically use the [generate-license-file](https://www.npmjs.com/package/generate-license-file) CLI
to bundle all dependency licenses with your build, ensuring effortless compliance.

---

Originally created by [SSbit01](https://ssbit01.github.io/).