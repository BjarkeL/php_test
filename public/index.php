<?php
declare(strict_types=1);
session_start();

/**
 * Optional Basic Auth for /admin (recommended on Azure)
 * Set env vars in Azure App Settings or locally if you want:
 *   ADMIN_USER=admin
 *   ADMIN_PASS=supersecret
 */
function admin_auth(): void {
  $u = getenv('ADMIN_USER') ?: '';
  $p = getenv('ADMIN_PASS') ?: '';
  if ($u === '' && $p === '') { return; } // auth disabled
  $ok = isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])
     && hash_equals($u, $_SERVER['PHP_AUTH_USER'])
     && hash_equals($p, $_SERVER['PHP_AUTH_PW']);
  if (!$ok) {
    header('WWW-Authenticate: Basic realm="Admin"');
    http_response_code(401);
    echo "Unauthorized";
    exit;
  }
}

function csrf_token(): string {
  if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
  }
  return $_SESSION['csrf'];
}
function csrf_check(string $token): void {
  if (!hash_equals($_SESSION['csrf'] ?? '', $token)) {
    http_response_code(419);
    echo "CSRF token mismatch";
    exit;
  }
}

/**
 * DB bootstrap:
 * Use MySQL when DB_DRIVER=mysql; otherwise SQLite.
 * Azure App Settings (example):
 *   DB_DRIVER=mysql
 *   DB_HOST=your-mysql.mysql.database.azure.com
 *   DB_PORT=3306
 *   DB_NAME=app
 *   DB_USER=appuser@your-mysql
 *   DB_PASS=strongpassword
 *   DB_SSL_CA=/home/site/wwwroot/certs/azure-mysql-ca.pem (optional)
 */
function pdo_connect(): PDO {
  $driver = strtolower(getenv('DB_DRIVER') ?: '');
  if ($driver === 'mysql') {
    $host = getenv('DB_HOST') ?: 'localhost';
    $port = getenv('DB_PORT') ?: '3306';
    $db   = getenv('DB_NAME') ?: 'app';
    $user = getenv('DB_USER') ?: '';
    $pass = getenv('DB_PASS') ?: '';
    $dsn = "mysql:host={$host};port={$port};dbname={$db};charset=utf8mb4";
    $opts = [
      PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
      PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
      PDO::ATTR_EMULATE_PREPARES => false,
    ];
    $ca = getenv('DB_SSL_CA');
    if ($ca && is_readable($ca)) {
      $opts[PDO::MYSQL_ATTR_SSL_CA] = $ca;
      // $opts[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = false; // not recommended
    }
    return new PDO($dsn, $user, $pass, $opts);
  }

  // SQLite (local dev)
  $dbPath = __DIR__ . '/../data/app.sqlite';
  @mkdir(dirname($dbPath), 0777, true);
  $pdo = new PDO('sqlite:' . $dbPath, null, null, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
  ]);
  $pdo->exec('PRAGMA foreign_keys = ON;');
  return $pdo;
}

$pdo = pdo_connect();

/** Run minimal, driver-aware migration on every boot (cheap and simple) */
function migrate(PDO $pdo): void {
  $driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
  if ($driver === 'mysql') {
    $pdo->exec("
      CREATE TABLE IF NOT EXISTS tasks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        is_done TINYINT(1) NOT NULL DEFAULT 0,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");
  } else {
    $pdo->exec("
      CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        is_done INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    ");
  }
}
migrate($pdo);

// -------- tiny router --------
$path   = strtok($_SERVER['REQUEST_URI'], '?') ?: '/';
$method = $_SERVER['REQUEST_METHOD'];

// CORS snippet (only if you need a Vite frontend on another origin)
// header('Access-Control-Allow-Origin: http://localhost:5173');
// header('Access-Control-Allow-Headers: Content-Type');
// header('Access-Control-Allow-Methods: GET,POST,PUT,PATCH,DELETE,OPTIONS');
// if ($method === 'OPTIONS') { exit; }

// API: GET /tasks
if ($path === '/tasks' && $method === 'GET') {
  header('Content-Type: application/json');
  echo json_encode($pdo->query('SELECT * FROM tasks ORDER BY id DESC')->fetchAll());
  exit;
}

// API: POST /tasks
if ($path === '/tasks' && $method === 'POST') {
  $input = json_decode(file_get_contents('php://input'), true) ?? [];
  if (!isset($input['title']) || !is_string($input['title']) || $input['title'] === '') {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'title is required']);
    exit;
  }
  $stmt = $pdo->prepare('INSERT INTO tasks (title) VALUES (:title)');
  $stmt->execute([':title' => $input['title']]);
  $id = (int)$pdo->lastInsertId();
  header('Content-Type: application/json');
  echo json_encode($pdo->query('SELECT * FROM tasks WHERE id = ' . $id)->fetch());
  exit;
}

// ADMIN: GET /admin (HTML)
if ($path === '/admin' && $method === 'GET') {
  admin_auth();
  $tasks = $pdo->query('SELECT id, title, is_done, created_at FROM tasks ORDER BY id DESC')->fetchAll();
  $token = htmlspecialchars(csrf_token(), ENT_QUOTES);
  $driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
  $dbLabel = $driver === 'mysql' ? 'MySQL (Azure-ready)' : 'SQLite (local)';
  ?>
  <!doctype html>
  <html>
  <head>
    <meta charset="utf-8" />
    <title>Admin · Tasks</title>
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <style>
      :root { --fg:#0b1021; --muted:#6b7280; --bg:#f9fafb; --card:#ffffff; --ok:#10b981; --err:#ef4444; }
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: var(--bg); color: var(--fg); margin: 2rem; }
      .card { background: var(--card); border-radius: 16px; padding: 1rem 1.25rem; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
      .row { display: flex; gap: 1rem; flex-wrap: wrap; align-items: start; }
      table { width: 100%; border-collapse: collapse; }
      th, td { padding: .5rem .6rem; border-bottom: 1px solid #eee; vertical-align: top; }
      th { text-align: left; font-weight: 600; font-size: .9rem; color: var(--muted); }
      .muted { color: var(--muted); }
      .btn { display: inline-block; padding: .45rem .7rem; border-radius: 10px; border: 1px solid #e5e7eb; background:#fff; cursor: pointer; text-decoration: none; }
      .btn.danger { border-color:#fecaca; background:#fff5f5; }
      .btn.primary { border-color:#bbf7d0; background:#ecfdf5; }
      .inline { display:inline; margin:0; }
      input[type="text"] { padding: .45rem .6rem; border-radius: 10px; border: 1px solid #e5e7eb; width: 22rem; }
      .pill { display:inline-block; padding:.1rem .45rem; border-radius:999px; font-size:.75rem; background:#f3f4f6; }
      .hdr { display:flex; justify-content:space-between; align-items:center; margin-bottom:.75rem; }
      .grid { display:grid; grid-template-columns: 1fr; gap: 1rem; }
      @media (min-width: 900px) { .grid { grid-template-columns: 1fr 2fr; } }
    </style>
  </head>
  <body>
    <div class="hdr">
      <h1>Tasks Admin</h1>
      <div class="muted">DB: <span class="pill"><?= htmlspecialchars($dbLabel, ENT_QUOTES) ?></span></div>
    </div>

    <div class="grid">
      <div class="card">
        <h3>Add Task</h3>
        <form method="post" action="/admin">
          <input type="hidden" name="csrf" value="<?= $token ?>" />
          <input type="hidden" name="action" value="create" />
          <p><input type="text" name="title" placeholder="Task title…" required /></p>
          <p><button class="btn primary" type="submit">Add</button></p>
        </form>
        <hr style="border:none;border-top:1px solid #eee;margin:1rem 0;">
        <form method="post" action="/admin" class="inline" onsubmit="return confirm('Delete ALL tasks?');">
          <input type="hidden" name="csrf" value="<?= $token ?>" />
          <input type="hidden" name="action" value="delete_all" />
          <button class="btn danger" type="submit">Delete all</button>
        </form>
      </div>

      <div class="card">
        <div class="hdr">
          <h3>All Tasks</h3>
          <div class="muted"><?= count($tasks) ?> rows</div>
        </div>
        <table>
          <thead><tr><th>ID</th><th>Title</th><th>Done</th><th>Created</th><th></th></tr></thead>
          <tbody>
          <?php foreach ($tasks as $t): ?>
            <tr>
              <td><?= (int)$t['id'] ?></td>
              <td><?= htmlspecialchars((string)$t['title'], ENT_QUOTES) ?></td>
              <td><?= ((int)$t['is_done']) ? '✓' : '—' ?></td>
              <td class="muted"><?= htmlspecialchars((string)$t['created_at'], ENT_QUOTES) ?></td>
              <td>
                <form method="post" action="/admin" class="inline" onsubmit="return confirm('Delete task #<?= (int)$t['id'] ?>?');">
                  <input type="hidden" name="csrf" value="<?= $token ?>" />
                  <input type="hidden" name="action" value="delete_one" />
                  <input type="hidden" name="id" value="<?= (int)$t['id'] ?>" />
                  <button class="btn danger" type="submit">Delete</button>
                </form>
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>

    <p class="muted" style="margin-top:1rem">
      API samples: <code>GET /tasks</code>,
      <code>POST /tasks {"title":"Hello"}</code>
    </p>
  </body>
  </html>
  <?php
  exit;
}

// ADMIN: POST /admin (create/delete)
if ($path === '/admin' && $method === 'POST') {
  admin_auth();
  $action = $_POST['action'] ?? '';
  $token  = (string)($_POST['csrf'] ?? '');
  csrf_check($token);

  if ($action === 'create') {
    $title = trim((string)($_POST['title'] ?? ''));
    if ($title === '') { header('Location: /admin'); exit; }
    $stmt = $pdo->prepare('INSERT INTO tasks (title) VALUES (:title)');
    $stmt->execute([':title' => $title]);
    header('Location: /admin'); exit;
  }

  if ($action === 'delete_one') {
    $id = (int)($_POST['id'] ?? 0);
    if ($id > 0) {
      $stmt = $pdo->prepare('DELETE FROM tasks WHERE id = :id');
      $stmt->execute([':id' => $id]);
    }
    header('Location: /admin'); exit;
  }

  if ($action === 'delete_all') {
    $pdo->exec('DELETE FROM tasks');
    header('Location: /admin'); exit;
  }

  http_response_code(400);
  echo "Unsupported action";
  exit;
}

// DEFAULT: Minimal landing page
?>
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>PHP + SQLite/MySQL quick test</title>
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <style>body{font-family:system-ui;margin:2rem;max-width:700px}</style>
  </head>
  <body>
    <h1>PHP + SQLite/MySQL quick test</h1>
    <p>
      Admin UI: <a href="/admin">/admin</a><br>
      API: <code>GET /tasks</code>, <code>POST /tasks</code> with JSON <code>{"title":"Try PHP"}</code>
    </p>
    <script>
      // Quick demo insert + load:
      (async function(){
        try {
          await fetch('/tasks', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({title:'Inserted from landing page'})});
          const r = await fetch('/tasks'); const tasks = await r.json();
          document.body.insertAdjacentHTML('beforeend', `<pre>${JSON.stringify(tasks, null, 2)}</pre>`);
        } catch(e) {}
      })();
    </script>
  </body>
</html>
