# Zorv Server Deployment

This directory provides three ways to run the server as a managed service: systemd (Linux), Docker, and a Windows service (NSSM).

## Common Configuration Notes

Edit the server config (`zorvd.toml`, template at [config/zorvd.example.toml](../config/zorvd.example.toml)) before deploying:

- `auth.token`: use a long, high-entropy random string shared with clients.
- `tls.cert_file` / `tls.key_file`: point to the PEM certificate and private key. For testing you can generate a self-signed cert with `cargo run --release --example gen_cert -- server.crt server.key`; use a trusted CA in production.
- `data_dir`: persistence directory for traffic stats etc. Point it to a dedicated location (`/var/lib/zorv` for systemd; the Docker image already uses `/var/lib/zorv`).
- With `admin.enabled = true`, set `admin.username` / `admin.password` (generate a PBKDF2 hash with `zorvd hash-password <plaintext>`), and optionally enable admin HTTPS via `[admin.tls]`.
- If a public proxy listen port is below 1024 (e.g. 80/443), make sure the process has the required privileges.

## 1. Linux / systemd

See the header comments of [zorvd.service](zorvd.service). Summary:

```sh
sudo useradd --system --home /var/lib/zorv --create-home --shell /usr/sbin/nologin zorv
sudo install -m 755 releases/zorvd /usr/local/bin/zorvd
sudo mkdir -p /etc/zorv
sudo cp config/zorvd.example.toml /etc/zorv/zorvd.toml   # edit: token, certs, data_dir = "/var/lib/zorv"
sudo cp releases/server.crt /etc/zorv/server.crt
sudo cp releases/server.key /etc/zorv/server.key
sudo cp deploy/zorvd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now zorvd
journalctl -u zorvd -f   # follow the logs
```

## 2. Docker

```sh
docker build -f deploy/Dockerfile -t zorvd:latest .
mkdir -p /srv/zorv/config && cp config/zorvd.example.toml /srv/zorv/config/zorvd.toml
# edit /srv/zorv/config/zorvd.toml: change token, point cert paths to /etc/zorv/* (see below), keep admin.listen = 0.0.0.0
docker run -d --name zorvd --restart unless-stopped \
  -p 8443:8443 -p 9000:9000 \
  -v /srv/zorv/config:/etc/zorv \
  -v /srv/zorv/data:/var/lib/zorv \
  zorvd:latest
```

- The image bundles the self-signed certs from `releases/`; to replace them, put your certs in the mounted `/srv/zorv/config/` directory and point the config at `/etc/zorv/server.crt` etc.
- Add extra `-p <port>:<port>` mappings for each proxy `listen` port as needed.
- `admin.listen` is set to `0.0.0.0:9000` by the Dockerfile — set a strong password and enforce firewall rules.

## 3. Windows service (NSSM)

- Build: `cargo build --release --bin zorvd` (artifact at `target\release\zorvd.exe`, or use `releases\zorvd.exe`).
- Install NSSM, add it to PATH, then run as administrator:

```powershell
powershell -ExecutionPolicy Bypass -File deploy\zorvd-windows-service.ps1
```

- The script uses the service name `zorvd` by default; override with `-ServiceName` / `-InstallDir` / `-ConfigPath`. Logs go to `zorvd.log` / `zorvd.err.log` in the install directory.
- Uninstall: `nssm stop zorvd; nssm remove zorvd confirm`

> Note: `zorvd.exe` is a plain CLI process, so a Windows service needs a wrapper. This setup uses NSSM; [WinSW](https://github.com/winsw/winsw) is an alternative with the same idea (wrap and manage the process lifecycle).
