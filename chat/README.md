# Private Chat (Railway + iPad Safari)

E2EE room-code chat. Server stores only ciphertext `{iv, data}`.

## Run locally
```
cd chat
npm install
npm start
```
Open http://localhost:3000

## Deploy to Railway
1. Push this `chat/` folder as its own repo (or Railway monorepo service with root = `chat/`).
2. Add a Volume, mount path `/data`, set env `DATA_DIR=/data` (otherwise filesystem is ephemeral and chats vanish on redeploy).
3. Deploy. HTTPS is automatic.

## How privacy works
- Code format `XXXX-XXXX`, kept in URL hash `#c=...` so it never hits server access logs.
- `roomId = SHA-256(code)`, `key = PBKDF2-SHA256(100k, code, salt=roomId)` → AES-GCM-256 via WebCrypto.
- Nickname lives in `sessionStorage`, sent only inside ciphertext.
- No accounts, no analytics, CSP `self` only. In-memory rate limit only.

## Keylogger note (honest limits)
- Secure-keys mode uses a custom keyboard with `pointerdown` handlers and no `<input>` focus, so commodity page-level `keydown/keypress/input` loggers never fire and the iOS system/third-party keyboard never opens.
- It does NOT stop OS-level loggers, MDM, screen capture, or malicious JS injected into the page. Anyone with the room code can read/write/delete.
- Railway edge/TLS still sees IPs. Zero-log is not achievable on hosted infra.

## API
- `POST /api/rooms {roomId}` — create (idempotent)
- `GET /api/rooms/:roomId/messages?since=ts`
- `POST /api/rooms/:roomId/messages {iv, data}` (base64)
- `DELETE /api/rooms/:roomId` — permanent delete
