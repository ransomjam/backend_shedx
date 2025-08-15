
# ProList Mock Backend (Express + Socket.IO)

Endpoints:
- `GET /api/health`
- `GET /api/products`
- `POST /api/products` (auth)
- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me` (auth)
- `POST /api/orders/checkout` (auth)
- `GET /api/messages/:chatId` (auth)

## Run locally
```bash
npm install
npm start
```
Set env (optional):
```
JWT_SECRET=your_secret
CORS_ORIGIN=exp://127.0.0.1:19000,exp://192.168.0.0/16,http://localhost:8081
SOCKET_ORIGIN=exp://127.0.0.1:19000,exp://192.168.0.0/16
```

## Deploy to Railway
- Ensure `start` script exists (already set)
- Set variables: `NODE_ENV`, `JWT_SECRET`, `CORS_ORIGIN`, `SOCKET_ORIGIN`
- Deploy with `railway up`
