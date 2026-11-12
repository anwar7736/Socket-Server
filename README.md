# Socket.IO server deployment

This server can run on a VPS independently of the Next.js app. The recommended setup is a dedicated HTTPS subdomain such as `socket.example.com`, reverse-proxied to the Node process on localhost.

## Docker

Build the image from this repository, then pass environment variables at runtime. Start by copying `.env.example` to `.env`; set `AUTH_SECRET` to the same random secret used by the Next.js app and set `CORS_ORIGINS` to the exact frontend origin(s).

```bash
docker build -t convo-socket-server .
docker run --name convo-socket-server \
  --env-file .env \
  -p 3002:3002 \
  convo-socket-server
```

The container exposes port `3002` and includes a health check at `/`. Keep `.env` out of the image and source control. For production, put the container behind an HTTPS/WebSocket-capable reverse proxy and set `CORS_ORIGINS` to the public frontend origin(s); the browser-facing `NEXT_PUBLIC_SOCKET_URL` must point to that public Socket.IO origin.

## Configure the app and server

1. Deploy the Next.js app to Vercel and add its production domain. For Vercel preview deployments, use a stable custom preview domain rather than allowing every `vercel.app` origin.
2. On Vercel, set `NEXT_PUBLIC_SOCKET_URL` to the public Socket.IO origin, for example `https://socket.example.com`. Set `AUTH_SECRET` to a cryptographically random value of at least 32 characters. These variables must be present for each environment and `NEXT_PUBLIC_SOCKET_URL` is read at build time, so redeploy after changing it.
3. Clone this repository on the VPS, install a supported Node.js LTS release, then install the lockfile dependencies:

   ```bash
   git clone https://github.com/anwar7736/Socket-Server.git
   cd Socket-Server
   npm ci
   ```

4. Create `.env` from `.env.example`. Set `PORT=3002`, use the exact same `AUTH_SECRET` value as Vercel, and list the exact frontend origins in `CORS_ORIGINS`, comma-separated:

   ```env
   PORT=3002
   CORS_ORIGINS=https://chat.example.com,https://preview.chat.example.com
   AUTH_SECRET=your-same-long-random-vercel-secret
   ```

   Keep `.env` private and never commit it. The Next.js app issues short-lived signed socket tickets through its authenticated API. The socket server verifies those tickets locally, so it does not need the session cookie or database.

## HTTPS reverse proxy

Point the `socket.example.com` DNS record at the VPS. Configure Nginx to forward the complete Socket.IO path and WebSocket upgrade to the Node service:

```nginx
server {
    listen 80;
    server_name socket.example.com;

    location / {
        proxy_pass http://127.0.0.1:3002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 75s;
        proxy_buffering off;
    }
}
```

Install a TLS certificate (for example, with Certbot) and serve the subdomain over HTTPS. Validate and reload Nginx with `sudo nginx -t && sudo systemctl reload nginx`. Keep port 3002 bound behind the VPS firewall; expose only SSH, HTTP, and HTTPS.

Run the server under a process manager so it survives SSH disconnects and reboots:

```bash
sudo npm install --global pm2
pm2 start server.js --name chat-socket
pm2 save
pm2 startup
```

Run the command printed by `pm2 startup` to enable boot-time startup.

## Check the deployment

```bash
curl https://socket.example.com/
curl "https://socket.example.com/socket.io/?EIO=4&transport=polling"
pm2 logs chat-socket
```

The root health check returns `{"status":"ok","service":"socket-server"}`. The Socket.IO polling endpoint returns an Engine.IO handshake. A browser connection also requires the app's valid, short-lived ticket and an origin listed in `CORS_ORIGINS`.

Use the exact frontend origin, including `https://` and any non-default port, in `CORS_ORIGINS`. Never use `*` or an untrusted broad origin. Socket presence and call state are in process memory; multiple VPS instances require shared Socket.IO and presence coordination.
