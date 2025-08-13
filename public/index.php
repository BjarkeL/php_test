<?php
declare(strict_types=1);
session_start();

/**
 * Azure MySQL connection via env vars:
 *   AZURE_MYSQL_DBNAME    (e.g., "app")
 *   AZURE_MYSQL_FLAG      optional gate; if "0" or "Disabled" -> refuse to run
 *   AZURE_MYSQL_HOST      (e.g., "myserver.mysql.database.azure.com")
 *   AZURE_MYSQL_PASSWORD  (the user's password)
 *   AZURE_MYSQL_PORT      (e.g., "3306")
 *   AZURE_MYSQL_USERNAME  (often "appuser@myserver")
 *
 * Optional admin auth for /admin:
 *   ADMIN_USER, ADMIN_PASS
 *
 * Optional TLS CA path (only if you want strict server cert validation):
 *   AZURE_MYSQL_SSL_CA    (e.g., "/home/site/wwwroot/certs/azure-mysql-ca.pem")
 */

function envv(string $key, ?string $default = null): string {
  $val = getenv($key);
  if ($val === false || $val === '') {
    if ($default !== null) return $default;
    throw new RuntimeException("Missing required env: {$key}");
  }
  return $val;
}

function admin_auth(): void {
  $u = getenv('ADMIN_USER') ?: '';
  $p = getenv('ADMIN_PASS') ?: '';
  if ($u === '' && $p === '') return; // disabled
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
  if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
  return $_SESSION['csrf'];
}
function csrf_check(string $token): void {
  if (!hash_equals($_SESSION['csrf'] ?? '', $token)) {
    http_response_code(419);
    echo "CSRF token mismatch";
    exit;
  }
}

function pdo_connect_azure(): PDO {
  $flag = getenv('AZURE_MYSQL_FLAG') ?: 'Enabled';
  if (in_array(strtolower($flag), ['0','disabled','false','off'], true)) {
    throw new RuntimeException('AZURE_MYSQL_FLAG indicates MySQL is disabled.');
  }

  $host = envv('AZURE_MYSQL_HOST');
  $port = envv('AZURE_MYSQL_PORT', '3306');
  $db   = envv('AZURE_MYSQL_DBNAME');
  $user = envv('AZURE_MYSQL_USERNAME');
  $pass = envv('AZURE_MYSQL_PASSWORD');

  $dsn = "mysql:host={$host};port={$port};dbname={$db};charset=utf8mb4";
  $opts = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
  ];

  // If you want strict TLS validation, supply AZURE_MYSQL_SSL_CA.
  $ca = getenv('AZURE_MYSQL_SSL_CA') ?: '';
  if ($ca !== '' && is_readable($ca)) {
    $opts[PDO::MYSQL_ATTR_SSL_CA] = $ca;
    // If you cannot validate server certs, you could disable verification,
    // but that's not recommended for production:
    // $opts[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = false;
  }

  return new PDO($dsn, $user, $pass, $opts);
}

function migrate(PDO $pdo): void {
  $pdo->exec("
    CREATE TABLE IF NOT EXISTS tasks (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      is_done TINYINT(1) NOT NULL DEFAULT 0,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  ");
}

// Bootstrap DB (Azure MySQL only)
try {
  $pdo = pdo_connect_azure();
  migrate($pdo);
} catch (Throwable $e) {
  http_response_code(500);
  header('Content-Type: text/plain; charset=utf-8');
  echo "Failed to connect to Azure MySQL.\n\n";
  echo "Error: " . $e->getMessage() . "\n\n";
  echo "Checklist:\n";
  echo "  - AZURE_MYSQL_HOST       = " . (getenv('AZURE_MYSQL_HOST') ? '[set]' : '[missing]') . "\n";
  echo "  - AZURE_MYSQL_PORT       = " . (getenv('AZURE_MYSQL_PORT') ?: '[missing]') . "\n";
  echo "  - AZURE_MYSQL_DBNAME     = " . (getenv('AZURE_MYSQL_DBNAME') ? '[set]' : '[missing]') . "\n";
  echo "  - AZURE_MYSQL_USERNAME   = " . (getenv('AZURE_MYSQL_USERNAME') ? '[set]' : '[missing]') . "\n";
  echo "  - AZURE_MYSQL_PASSWORD   = " . (getenv('AZURE_MYSQL_PASSWORD') ? '[set]' : '[missing]') . "\n";
  echo "  - AZURE_MYSQL_FLAG       = " . (getenv('AZURE_MYSQL_FLAG') ?: '[unset -> defaults Enabled]') . "\n";
  echo "  - AZURE_MYSQL_SSL_CA     = " . (getenv('AZURE_MYSQL_SSL_CA') ? '[set]' : '[unset]') . "\n\n";
  echo "Note: username is often 'user@servername' for Azure Flexible Server.\n";
  exit;
}

// ---------------- tiny router ----------------
$path   = strtok($_SERVER['REQUEST_URI'], '?') ?: '/';
$method = $_SERVER['REQUEST_METHOD'];

// API: GET /tasks
if ($path === '/tasks' && $method === 'GET') {
  header('Content-Type: application/json');
  echo json_encode($pdo->query('SELECT * FROM tasks ORDER BY id DESC')->fetchAll());
  exit;
}

// API: POST /tasks  (body: {"title":"..."})
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
  ?>
  <!doctype html>
  <html>
  <head>
    <meta charset="utf-8" />
    <title>Admin · Tasks (Azure MySQL)</title>
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <style>
      :root { --fg:#0b1021; --muted:#6b7280; --bg:#f9fafb; --card:#ffffff; }
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: var(--bg); color: var(--fg); margin: 2rem; }
      .card { background: var(--card); border-radius: 16px; padding: 1rem 1.25rem; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
      .hdr { display:flex; justify-content:space-between; align-items:center; margin-bottom:.75rem; }
      .muted { color: var(--muted); }
      .btn { display:inline-block; padding:.45rem .7rem; border-radius:10px; border:1px solid #e5e7eb; background:#fff; cursor:pointer; }
      .btn.danger { border-color:#fecaca; background:#fff5f5; }
      .btn.primary { border-color:#bbf7d0; background:#ecfdf5; }
      input[type="text"] { padding:.45rem .6rem; border-radius:10px; border:1px solid #e5e7eb; width:22rem; }
      table { width:100%; border-collapse:collapse; }
      th, td { padding:.5rem .6rem; border-bottom:1px solid #eee; text-align:left; vertical-align:top; }
    </style>
  </head>
  <body>
    <div class="hdr">
      <h1>Tasks Admin</h1>
      <div class="muted">DB: Azure MySQL</div>
    </div>

    <div class="card" style="margin-bottom:1rem">
      <h3>Add Task</h3>
      <form method="post" action="/admin">
        <input type="hidden" name="csrf" value="<?= $token ?>" />
        <input type="hidden" name="action" value="create" />
        <p><input type="text" name="title" placeholder="Task title…" required /></p>
        <p><button class="btn primary" type="submit">Add</button></p>
      </form>
      <hr style="border:none;border-top:1px solid #eee;margin:1rem 0;">
      <form method="post" action="/admin" onsubmit="return confirm('Delete ALL tasks?');">
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
              <form method="post" action="/admin" onsubmit="return confirm('Delete task #<?= (int)$t['id'] ?>?');" style="display:inline">
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

    <p class="muted" style="margin-top:1rem">
      API: <code>GET /tasks</code>,
      <code>POST /tasks {"title":"Hello"}</code>
    </p>
  </body>
  </html>
  <?php
  exit;
}

// ADMIN: POST /admin
if ($path === '/admin' && $method === 'POST') {
  admin_auth();
  $action = $_POST['action'] ?? '';
  $token  = (string)($_POST['csrf'] ?? '');
  csrf_check($token);

  if ($action === 'create') {
    $title = trim((string)($_POST['title'] ?? ''));
    if ($title !== '') {
      $stmt = $pdo->prepare('INSERT INTO tasks (title) VALUES (:title)');
      $stmt->execute([':title' => $title]);
    }
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

// DEFAULT: landing
?>
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>PHP · Azure MySQL demo</title>
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <style>body{font-family:system-ui;margin:2rem;max-width:700px}</style>
  </head>
  <body>
    <h1>PHP · Azure MySQL demo</h1>
    <p>
      Admin UI: <a href="/admin">/admin</a><br>
      API: <code>GET /tasks</code>, <code>POST /tasks</code> with JSON <code>{"title":"Try PHP"}</code>
    </p>
    <script>
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
