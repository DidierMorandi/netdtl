<?php
// ============================================================
//  NetDTL v3.0 — Inventaire des machines
// ============================================================
require_once __DIR__ . '/db.php';
requireAuth();
session_start();
initDB();

$pdo = getDB();
$message = ''; $msgType = '';

// ─── IP locale du serveur ───────────────────────────────────
$serverIP = $_SERVER['SERVER_ADDR'] ?? gethostbyname(gethostname());

// ─── Ajout manuel ───────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_machine'])) {
    $hostname = trim($_POST['hostname'] ?? '');
    $ip       = trim($_POST['ip'] ?? '');
    $os       = normalizeOsLabel(trim($_POST['os'] ?? '')) ?? '';
    $comment  = trim($_POST['comment'] ?? '');

    if (!$hostname || !filter_var($ip, FILTER_VALIDATE_IP)) {
        $message = 'Hostname et IP valide requis.'; $msgType = 'error';
    } else {
        try {
            $switch_port = trim($_POST['switch_port'] ?? '');
            $patch_port  = trim($_POST['patch_port']  ?? '');
            $stmt = $pdo->prepare("INSERT INTO machines (hostname, ip, os, switch_port, patch_port, comment) VALUES (?,?,?,?,?,?)");
            $stmt->execute([$hostname, $ip, $os ?: null, $switch_port ?: null, $patch_port ?: null, $comment ?: null]);
            $message = "Machine $hostname ($ip) ajoutée."; $msgType = 'success';
        } catch (PDOException $e) {
            $message = 'Erreur : IP déjà existante ou problème BDD.'; $msgType = 'error';
        }
    }
}

// ─── Suppression ────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    $id = (int)$_POST['delete_id'];
    $pdo->prepare("DELETE FROM machines WHERE id=?")->execute([$id]);
    $message = 'Machine supprimée.'; $msgType = 'success';
}

// ─── Ping rapide d'une machine ───────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ping_id'])) {
    $id = (int)$_POST['ping_id'];
    $machine = $pdo->prepare("SELECT ip FROM machines WHERE id=?");
    $machine->execute([$id]);
    $m = $machine->fetch();
    if ($m) {
        $lines  = runPing($m['ip']);
        $stats  = parsePingStats($lines);
        $status = $stats['recv'] > 0 ? 'up' : 'down';
        $pdo->prepare("UPDATE machines SET status=?, last_ping_ms=?, last_seen=NOW() WHERE id=?")
            ->execute([$status, $stats['avg_ms'], $id]);
        $message = "Ping {$m['ip']} : $status" . ($stats['avg_ms'] ? " ({$stats['avg_ms']} ms)" : '');
        $msgType = $status === 'up' ? 'success' : 'error';
    }
}

// ─── Ping de tout l'inventaire ───────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ping_all'])) {
    $machines = $pdo->query("SELECT id, ip FROM machines")->fetchAll();
    $up = 0; $down = 0;
    foreach ($machines as $m) {
        $lines  = runPing($m['ip']);
        $stats  = parsePingStats($lines);
        $status = $stats['recv'] > 0 ? 'up' : 'down';
        $pdo->prepare("UPDATE machines SET status=?, last_ping_ms=?, last_seen=NOW() WHERE id=?")
            ->execute([$status, $stats['avg_ms'], $m['id']]);
        $status === 'up' ? $up++ : $down++;
    }
    $message = "Ping global terminé : $up en ligne, $down hors ligne.";
    $msgType = 'success';
}

// ─── Export CSV ──────────────────────────────────────────────
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    $machines = $pdo->query("SELECT hostname,ip,mac,vendor,switch_port,patch_port,os,status,open_ports,last_ping_ms,last_seen,comment FROM machines ORDER BY INET_ATON(ip)")->fetchAll();
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="inventaire_' . date('Ymd_His') . '.csv"');
    echo "\xEF\xBB\xBF";
    echo '"Hostname","IP","MAC","Fabricant","Port switch","Brassage","OS","Statut","Ports ouverts","Ping (ms)","Dernière vue","Commentaire"' . "\r\n";
    foreach ($machines as $m) {
        $m['os'] = normalizeOsLabel($m['os']) ?? '';
        echo implode(',', array_map(fn($v) => '"' . str_replace('"','""',$v??'') . '"', $m)) . "\r\n";
    }
    exit;
}

// ─── Filtres & recherche ────────────────────────────────────
$search = trim($_GET['q'] ?? '');
$filter = $_GET['status'] ?? '';
$where  = []; $params = [];
if ($search) { $where[] = "(hostname LIKE ? OR ip LIKE ? OR os LIKE ? OR comment LIKE ?)"; $p = "%$search%"; $params = array_merge($params,[$p,$p,$p,$p]); }
if (in_array($filter,['up','down','unknown'])) { $where[] = "status=?"; $params[] = $filter; }
$sql = "SELECT * FROM machines" . ($where ? ' WHERE '.implode(' AND ',$where) : '') . " ORDER BY INET_ATON(ip)";
$stmt = $pdo->prepare($sql); $stmt->execute($params);
$machines = $stmt->fetchAll();

$total   = (int)$pdo->query("SELECT COUNT(*) FROM machines")->fetchColumn();
$upCount = (int)$pdo->query("SELECT COUNT(*) FROM machines WHERE status='up'")->fetchColumn();
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetDTL — Inventaire</title>
<?php include __DIR__ . '/style.php'; ?>
<style>
.filter-bar { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.filter-btn { padding:4px 12px; border-radius:20px; border:1px solid var(--border2); background:none; color:var(--txt2); font-size:11px; font-family:var(--sans); cursor:pointer; text-decoration:none; transition:background .15s; }
.filter-btn:hover,.filter-btn.active { background:rgba(88,166,255,.15); color:var(--accent2); border-color:var(--accent2); }
.modal-overlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,.6); z-index:100; align-items:center; justify-content:center; }
.modal-overlay.open { display:flex; }
.modal { background:var(--bg2); border:1px solid var(--border2); border-radius:10px; padding:24px; width:420px; display:flex; flex-direction:column; gap:14px; }
.modal-title { font-size:14px; font-weight:600; color:var(--txt); }
.modal-actions { display:flex; gap:8px; justify-content:flex-end; margin-top:4px; }
</style>
</head>
<body>
<?php include __DIR__ . '/topbar.php'; ?>
<div class="layout">
<?php include __DIR__ . '/sidebar.php'; ?>
<main class="main">

    <!-- Toolbar -->
    <div class="toolbar">
        <form method="get" style="display:contents">
            <input type="text" name="q" placeholder="Recherche hostname, IP, OS…" value="<?= htmlspecialchars($search) ?>">
        </form>
        <form method="post" style="display:contents">
            <button type="submit" name="ping_all" value="1" class="export-btn">◎ Ping tout</button>
        </form>
        <button class="run-btn" onclick="document.getElementById('add-modal').classList.add('open')">+ Ajouter</button>
        <a href="?export=csv" class="export-btn">↓ CSV</a>
    </div>

    <div class="content">
        <div class="page-title">Inventaire des machines</div>

        <?php if ($message): ?>
        <div class="<?= $msgType==='error'?'error-box':'success-box' ?>"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>

        <!-- Stats + filtres -->
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
            <div class="stats-grid" style="flex:1;min-width:300px">
                <div class="stat-card"><div class="stat-label">Total</div><div class="stat-val"><?= $total ?></div></div>
                <div class="stat-card"><div class="stat-label">En ligne</div><div class="stat-val green"><?= $upCount ?></div></div>
                <div class="stat-card"><div class="stat-label">Résultats</div><div class="stat-val amber"><?= count($machines) ?></div></div>
            </div>
            <div class="filter-bar">
                <a href="inventory.php" class="filter-btn <?= !$filter?'active':'' ?>">Tous</a>
                <a href="?status=up<?= $search?"&q=".urlencode($search):'' ?>"   class="filter-btn <?= $filter==='up'?'active':'' ?>">● Up</a>
                <a href="?status=down<?= $search?"&q=".urlencode($search):'' ?>" class="filter-btn <?= $filter==='down'?'active':'' ?>">● Down</a>
                <a href="?status=unknown<?= $search?"&q=".urlencode($search):'' ?>" class="filter-btn <?= $filter==='unknown'?'active':'' ?>">? Inconnu</a>
            </div>
        </div>

        <!-- Table inventaire -->
        <div class="panel">
            <table class="data-table">
                <thead><tr>
                    <th>Statut</th><th>Hostname</th><th>IP</th><th>MAC</th><th>Fabricant</th><th>Port switch</th><th>Brassage</th><th>OS</th><th>Commentaire</th><th>Actions</th>
                </tr></thead>
                <tbody>
                <?php if (!$machines): ?>
                    <tr><td colspan="10" class="empty-cell">Aucune machine trouvée. Lancez une découverte réseau ou ajoutez une machine manuellement.</td></tr>
                <?php endif; ?>
                <?php foreach ($machines as $m): ?>
                <tr>
                    <td><?php
                        $cls = $m['status']==='up'?'badge-up':($m['status']==='down'?'badge-down':'badge-unknown');
                        $lbl = $m['status']==='up'?'up':($m['status']==='down'?'down':'?');
                        echo "<span class='badge $cls'>$lbl</span>";
                    ?></td>
                    <td><a href="machine.php?id=<?= $m['id'] ?>" class="link"><?= htmlspecialchars($m['hostname']) ?></a></td>
                    <td class="mono"><?= htmlspecialchars($m['ip']) ?></td>
                    <td class="mono muted small"><?php
                        if ($m['ip'] === $serverIP) {
                            echo '<span style="color:var(--accent2);font-style:italic">ce PC</span>';
                        } else {
                            echo htmlspecialchars($m['mac'] ?? '—');
                        }
                    ?></td>
                    <td class="muted small"><?= htmlspecialchars($m['vendor'] ?? '—') ?></td>
                    <td class="mono small" style="color:var(--accent2)"><?= htmlspecialchars($m['switch_port'] ?? '—') ?></td>
                    <td class="mono small" style="color:var(--purple)"><?= htmlspecialchars($m['patch_port'] ?? '—') ?></td>
                    <td class="muted small"><?= htmlspecialchars(normalizeOsLabel($m['os'] ?? '') ?? '—') ?></td>
                    <td class="muted small"><?= htmlspecialchars($m['comment'] ?? '—') ?></td>
                    <td>
                        <div style="display:flex;gap:6px">
                            <form method="post" style="display:inline">
                                <input type="hidden" name="ping_id" value="<?= $m['id'] ?>">
                                <button type="submit" class="export-btn" style="padding:3px 8px;font-size:10px">◎</button>
                            </form>
                            <a href="machine.php?id=<?= $m['id'] ?>" class="export-btn" style="padding:3px 8px;font-size:10px">⊞</a>
                            <form method="post" style="display:inline" onsubmit="return confirm('Supprimer cette machine ?')">
                                <input type="hidden" name="delete_id" value="<?= $m['id'] ?>">
                                <button type="submit" class="danger-btn" style="padding:3px 8px;font-size:10px">✕</button>
                            </form>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>

    </div>
</main>
</div>

<!-- Modal ajout machine -->
<div class="modal-overlay" id="add-modal" onclick="if(event.target===this)this.classList.remove('open')">
    <div class="modal">
        <div class="modal-title">⊞ Ajouter une machine</div>
        <form method="post" style="display:flex;flex-direction:column;gap:12px">
            <div class="form-grid">
                <div class="form-group">
                    <label class="form-label">Hostname *</label>
                    <input type="text" name="hostname" class="form-input" placeholder="PC-BUREAU-01" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Adresse IP *</label>
                    <input type="text" name="ip" class="form-input" placeholder="172.17.7.10" required>
                </div>
            </div>
            <div class="form-group">
                <label class="form-label">Système d'exploitation</label>
                <input type="text" name="os" class="form-input" placeholder="Windows 11 Pro">
            </div>
            <div class="form-group">
                <label class="form-label">Commentaire</label>
                <textarea name="comment" class="form-textarea" placeholder="PC direction, salle serveur…"></textarea>
            </div>
            <div class="modal-actions">
                <button type="button" class="export-btn" onclick="document.getElementById('add-modal').classList.remove('open')">Annuler</button>
                <button type="submit" name="add_machine" value="1" class="run-btn">Ajouter</button>
            </div>
        </form>
    </div>
</div>
</body>
</html>
