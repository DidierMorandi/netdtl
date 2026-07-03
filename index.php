<?php
// ============================================================
//  NetDTL v3.0 — Tableau de bord
// ============================================================
require_once __DIR__ . '/db.php';
requireAuth();
session_start();
initDB();

$pdo = getDB();

// ─── Stats globales ─────────────────────────────────────────
$total     = (int)$pdo->query("SELECT COUNT(*) FROM machines")->fetchColumn();
$up        = (int)$pdo->query("SELECT COUNT(*) FROM machines WHERE status='up'")->fetchColumn();
$down      = (int)$pdo->query("SELECT COUNT(*) FROM machines WHERE status='down'")->fetchColumn();
$unknown   = (int)$pdo->query("SELECT COUNT(*) FROM machines WHERE status='unknown'")->fetchColumn();
$lastScan  = $pdo->query("SELECT scan_date, hosts_up, network FROM scan_history ORDER BY id DESC LIMIT 1")->fetch();
$recentMachines = $pdo->query("SELECT * FROM machines ORDER BY last_seen DESC LIMIT 8")->fetchAll();
$recentDiag = $pdo->query("SELECT * FROM diag_history ORDER BY id DESC LIMIT 5")->fetchAll();
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetDTL — Tableau de bord</title>
<?php include __DIR__ . '/style.php'; ?>
</head>
<body>
<?php include __DIR__ . '/topbar.php'; ?>
<div class="layout">
<?php include __DIR__ . '/sidebar.php'; ?>
<main class="main">
<div class="content">

    <div class="page-title">Tableau de bord</div>

    <!-- Stats globales -->
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-label">Total machines</div>
            <div class="stat-val"><?= $total ?></div>
        </div>
        <div class="stat-card">
            <div class="stat-label">En ligne</div>
            <div class="stat-val green"><?= $up ?></div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Hors ligne</div>
            <div class="stat-val <?= $down > 0 ? 'red' : '' ?>"><?= $down ?></div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Inconnu</div>
            <div class="stat-val amber"><?= $unknown ?></div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Dernier scan</div>
            <div class="stat-val" style="font-size:13px"><?= $lastScan ? timeAgo($lastScan['scan_date']) : '—' ?></div>
        </div>
    </div>

    <!-- Machines récentes -->
    <div class="panel">
        <div class="panel-header">
            Machines récemment vues
            <a href="inventory.php" class="panel-link">Voir tout →</a>
        </div>
        <table class="data-table">
            <thead><tr>
                <th>Statut</th><th>Hostname</th><th>IP</th><th>OS</th><th>Dernière vue</th><th>Ping</th>
            </tr></thead>
            <tbody>
            <?php if (!$recentMachines): ?>
                <tr><td colspan="6" class="empty-cell">Aucune machine — lancez une découverte réseau.</td></tr>
            <?php endif; ?>
            <?php foreach ($recentMachines as $m): ?>
            <tr>
                <td><?php
                    $cls = $m['status'] === 'up' ? 'badge-up' : ($m['status'] === 'down' ? 'badge-down' : 'badge-unknown');
                    $lbl = $m['status'] === 'up' ? 'up' : ($m['status'] === 'down' ? 'down' : '?');
                    echo "<span class='badge $cls'>$lbl</span>";
                ?></td>
                <td><a href="machine.php?id=<?= $m['id'] ?>" class="link"><?= htmlspecialchars($m['hostname']) ?></a></td>
                <td class="mono"><?= htmlspecialchars($m['ip']) ?></td>
                <td class="muted"><?= htmlspecialchars(normalizeOsLabel($m['os'] ?? '') ?? '—') ?></td>
                <td class="muted small"><?= timeAgo($m['last_seen']) ?></td>
                <td class="mono small"><?= $m['last_ping_ms'] !== null ? $m['last_ping_ms'] . ' ms' : '—' ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- Derniers diagnostics -->
    <div class="panel">
        <div class="panel-header">
            Derniers diagnostics
            <a href="menu.php" class="panel-link">Outils →</a>
        </div>
        <div class="history-list">
        <?php if (!$recentDiag): ?>
            <div class="empty-cell" style="padding:16px">Aucun diagnostic effectué.</div>
        <?php endif; ?>
        <?php foreach ($recentDiag as $d): ?>
            <div class="history-item">
                <span class="h-badge h-<?= strtolower($d['action']) ?>"><?= htmlspecialchars($d['action']) ?></span>
                <span class="h-target"><?= htmlspecialchars($d['target']) ?></span>
                <span class="h-time"><?= timeAgo($d['created']) ?></span>
                <span class="<?= $d['success'] ? 'h-ok' : 'h-fail' ?>"><?= $d['success'] ? '✓' : '✗' ?></span>
            </div>
        <?php endforeach; ?>
        </div>
    </div>

</div>
</main>
</div>
</body>
</html>
