# Securing Remote Access to EMS-ESP Behind Apache — Cookie-Based Auth Without a VPN

## The problem

EMS-ESP's own web UI password isn't considered strong security by its own documentation. The obvious fix is to put it behind a reverse proxy with real authentication — but EMS-ESP's dashboard is a single-page app that keeps a **persistent WebSocket connection** open (`/ws`) for live data, plus background `fetch()` calls to `/api/...`. Standard **HTTP Basic Auth** (`Require valid-user`) on the whole site breaks this: browsers don't reliably carry Basic Auth credentials through a WebSocket handshake the way they do a normal page load, so the live dashboard degrades or reconnect-loops the moment the whole vhost is gated with Basic Auth.

**Solution:** a small PHP login page that sets a session cookie. Cookies are attached automatically to *every* request type on a domain — page loads, `fetch()` calls, and WebSocket upgrade handshakes alike — so there's no auth-header compatibility problem. Apache checks for a valid session cookie before deciding whether to proxy the request through to the device.

## Prerequisites

- Apache with `mod_rewrite`, `mod_proxy`, `mod_proxy_wstunnel`, and `mod_ssl` enabled
- PHP with session support (tested on PHP 7.4)
- A reverse proxy vhost already pointed at your device (`ProxyPass` / `ProxyPassReverse`)
- Ability to fully stop/start Apache (not just reload) — required when editing one of the two PHP files, explained below

## Architecture

```
Browser → https://your-gateway-domain/
             │
             ▼
        Apache RewriteRule checks for a valid session cookie
             │
      ┌──────┴──────┐
      │             │
   no/invalid     valid
      │             │
      ▼             ▼
  login.php    proxied through to the device (ProxyPass)
```

The validity check is done via Apache's `RewriteMap prg:` — an external program Apache keeps running as a **long-lived persistent process**, feeding it session IDs on stdin and reading back `1`/`0` on stdout for each request. This avoids spawning a new PHP process per request.

## Files

Both files live in one folder, aliased into the vhost:

```
C:/xampp/htdocs/ems-esp-auth/
    login.php
    check_session.php
```

### `login.php`

Serves the login form and sets the session cookie on success.

```php
<?php
define('EMS_ESP_PASSWORD_HASH', '$2y$10$abcdefg...'); // generate with password_hash()

session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (password_verify($_POST['password'], EMS_ESP_PASSWORD_HASH)) {
        $_SESSION['ems_esp_authenticated'] = true;
        $_SESSION['ems_esp_expires'] = time() + 1800; // 30-minute sliding session
        header('Location: /');
        exit;
    }
    $error = "Invalid password";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EMS-ESP Login</title>
<style>
    body {
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
        margin: 0;
        font-family: system-ui, sans-serif;
        background: #f2f2f2;
    }
    form {
        display: flex;
        flex-direction: column;
        gap: 12px;
        width: 100%;
        max-width: 320px;
        padding: 24px;
        box-sizing: border-box;
        background: #fff;
        border-radius: 8px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    input[type="password"] {
        font-size: 16px; /* prevents iOS auto-zoom on focus */
        padding: 10px;
        box-sizing: border-box;
        border: 1px solid #ccc;
        border-radius: 4px;
    }
    button {
        font-size: 16px;
        padding: 10px;
        border: none;
        border-radius: 4px;
        background: #333;
        color: #fff;
        cursor: pointer;
    }
    .error {
        color: #c00;
        margin: 0;
    }
</style>
</head>
<body>
<form method="post">
    <?php if (!empty($error)): ?>
        <p class="error"><?= htmlspecialchars($error) ?></p>
    <?php endif; ?>
    <input type="password" name="password" placeholder="Password" required autofocus>
    <button type="submit">Log in</button>
</form>
</body>
</html>
```

Generate the password hash once from a command line:
```
php -r "echo password_hash('your-chosen-password', PASSWORD_DEFAULT);"
```

### `check_session.php`

Runs as a persistent CLI process. Apache's `RewriteMap` feeds it one session ID per line via stdin; it responds `1` (valid) or `0` (invalid/expired) per line on stdout.

```php
<?php
if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit;
}

ini_set('session.save_path', 'C:/xampp/tmp'); // must match the save_path mod_php actually uses
ob_start(); // opened once, left open for the process's entire lifetime — see "Gotchas" below

while ($line = fgets(STDIN)) {
    $sid = trim($line);
    session_id($sid);
    session_start();

    $valid = !empty($_SESSION['ems_esp_authenticated'])
           && !empty($_SESSION['ems_esp_expires'])
           && $_SESSION['ems_esp_expires'] > time();

    if ($valid) {
        $_SESSION['ems_esp_expires'] = time() + 1800; // sliding expiry
    }

    session_write_close();

    fwrite(STDOUT, ($valid ? "1" : "0") . "\n"); // direct pipe write — bypasses PHP's output buffering
}
```

### Apache vhost

```apache
<VirtualHost *:443>
    ServerName your-gateway-domain

    SSLEngine on
    SSLCertificateFile "..."
    SSLCertificateKeyFile "..."
    SSLCertificateChainFile "..."

    Alias /ems-esp-auth "C:/xampp/htdocs/ems-esp-auth"
    <Directory "C:/xampp/htdocs/ems-esp-auth">
        Require all granted
    </Directory>

    RewriteEngine On
    RewriteMap session_check "prg:C:/xampp/php/php.exe C:/xampp/htdocs/ems-esp-auth/check_session.php"

    RewriteRule ^/ems-esp-auth/ - [L]

    RewriteCond %{HTTP_COOKIE} !PHPSESSID=([^;]+) [NC]
    RewriteRule ^ /ems-esp-auth/login.php [L,R=302]

    RewriteCond %{HTTP_COOKIE} PHPSESSID=([^;]+) [NC]
    RewriteCond ${session_check:%1} !^1$
    RewriteRule ^ /ems-esp-auth/login.php [L,R=302]

    ProxyPreserveHost On
    ProxyPass /ems-esp-auth !
    ProxyPass /ws ws://192.168.x.x/ws
    ProxyPassReverse /ws ws://192.168.x.x/ws
    ProxyPass / http://192.168.x.x/
    ProxyPassReverse / http://192.168.x.x/
</VirtualHost>
```

## Gotchas encountered (and why the code looks the way it does)

- **`ProxyPass /ems-esp-auth !`** — without this, `mod_proxy` claims the `/ems-esp-auth/` path ahead of the rewrite rules regardless of directive order, and requests for `login.php` get silently forwarded to the proxied device instead of served locally (symptom: blank white page).
- **`session_start()` after any output has occurred fails silently with a warning** — not just from a UTF-8 BOM or stray whitespace before `<?php`, but structurally: since `check_session.php` is a *persistent* process handling many requests in its lifetime, the very first `echo`/`fwrite` in iteration 1 permanently marks "output has happened" for the rest of the process's life, breaking `session_start()` on every later iteration. Fixed by opening `ob_start()` once, before the loop, and writing the actual response with `fwrite(STDOUT, ...)`, which bypasses PHP's output-tracking entirely.
- **`stream_set_write_buffer(STDOUT, 0)` is unreliable on Windows PHP builds** and caused a hard crash (access violation) in testing — avoid it; `fwrite(STDOUT, ...)` alone is sufficient.
- **The `prg:` process is long-lived and does not restart on file save.** Any edit to `check_session.php` requires a full Apache **stop, then start** (not a graceful reload/restart) to take effect, since Apache doesn't respawn the external program on its own.
- **Cookie domain scoping** — the login page must be served under the *same hostname* the proxy/rewrite rules live on. A cookie set on one subdomain is invisible to a different subdomain.
- **Mobile viewport** — without `<meta name="viewport" content="width=device-width, initial-scale=1.0">`, mobile browsers render the login form at desktop scale and shrink it. Input font-size should stay ≥16px to avoid iOS auto-zoom on focus.

## Result

Full remote access to the EMS-ESP dashboard — including live WebSocket data — gated behind a proper session login, no VPN required, and no interference with the SPA's live traffic.
