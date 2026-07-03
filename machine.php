<?php
// ============================================================
//  NetDTL v3.0 — Fiche machine
// ============================================================
require_once __DIR__ . '/db.php';
requireAuth();
session_start();
initDB();

$pdo = getDB();
$id  = (int)($_GET['id'] ?? 0);
$machine = $pdo->prepare("SELECT * FROM machines WHERE id=?");
$machine->execute([$id]);
$m = $machine->fetch();
if (!$m) { header('Location: inventory.php'); exit; }

$message = ''; $msgType = '';
$diagLines = []; $diagAction = '';

// ─── Mise à jour commentaire / OS ───────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save'])) {
    $os          = normalizeOsLabel(trim($_POST['os'] ?? '')) ?? '';
    $switch_port = trim($_POST['switch_port'] ?? '');
    $patch_port  = trim($_POST['patch_port']  ?? '');
    $comment     = trim($_POST['comment'] ?? '');
    $pdo->prepare("UPDATE machines SET os=?, switch_port=?, patch_port=?, comment=? WHERE id=?")->execute([$os ?: null, $switch_port ?: null, $patch_port ?: null, $comment ?: null, $id]);
    $message = 'Fiche mise à jour.'; $msgType = 'success';
    $m['os'] = $os; $m['switch_port'] = $switch_port; $m['patch_port'] = $patch_port; $m['comment'] = $comment;
}

// ─── Actions de diagnostic depuis la fiche ───────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['diag'])) {
    $diagAction = $_POST['diag'];
    switch ($diagAction) {
        case 'ping':
            $diagLines = runPing($m['ip']);
            $stats = parsePingStats($diagLines);
            $status = $stats['recv'] > 0 ? 'up' : 'down';
            $pdo->prepare("UPDATE machines SET status=?, last_ping_ms=?, last_seen=NOW() WHERE id=?")
                ->execute([$status, $stats['avg_ms'], $id]);
            $m['status'] = $status; $m['last_ping_ms'] = $stats['avg_ms'];
            break;
        case 'ports':
            $diagLines = runCommand(NMAP_PATH . ' -p 21,22,23,25,80,110,143,443,445,3306,3389,5900,8080 ' . escapeshellarg($m['ip']));
            // Mise à jour des ports dans la BDD
            $ports = [];
            foreach ($diagLines as $l) {
                if (preg_match('/^(\d+)\/(tcp|udp)\s+open\s+(\S+)/i', $l, $pm)) {
                    $ports[] = $pm[1].'/'.$pm[3];
                }
            }
            if ($ports) {
                $pdo->prepare("UPDATE machines SET open_ports=? WHERE id=?")->execute([implode(', ', $ports), $id]);
                $m['open_ports'] = implode(', ', $ports);
            }
            break;
        case 'traceroute':
            $diagLines = runCommand('tracert ' . escapeshellarg($m['ip']));
            break;
        case 'dns':
            $diagLines = runCommand('nslookup ' . escapeshellarg($m['ip']));
            break;
        case 'nmap_os':
            $diagLines = runCommand(NMAP_PATH . ' -O --host-timeout 10s ' . escapeshellarg($m['ip']));
            // Tente d'extraire l'OS
            foreach ($diagLines as $l) {
                if (preg_match('/OS details:\s+(.+)/i', $l, $om)) {
                    $detectedOs = normalizeOsLabel(trim($om[1]));
                    $pdo->prepare("UPDATE machines SET os=? WHERE id=?")->execute([$detectedOs, $id]);
                    $m['os'] = $detectedOs;
                }
            }
            break;
    }
    // Log en BDD
    $pdo->prepare("INSERT INTO diag_history (action, target, result, success) VALUES (?,?,?,1)")
        ->execute([$diagAction, $m['ip'], implode("\n", array_slice($diagLines, 0, 20))]);
}

$statusCls = $m['status']==='up'?'badge-up':($m['status']==='down'?'badge-down':'badge-unknown');
$statusLbl = $m['status']==='up'?'En ligne':($m['status']==='down'?'Hors ligne':'Inconnu');
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetDTL — <?= htmlspecialchars($m['hostname']) ?></title>
<?php include __DIR__ . '/style.php'; ?>
</head>
<body>
<?php include __DIR__ . '/topbar.php'; ?>
<div class="layout">
<?php include __DIR__ . '/sidebar.php'; ?>
<main class="main">
<div class="content">

    <!-- Entête machine -->
    <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">
        <div>
            <div class="page-title"><?= htmlspecialchars($m['hostname']) ?></div>
            <div class="muted small" style="margin-top:4px">Première vue : <?= $m['first_seen'] ?></div>
        </div>
        <span class="badge <?= $statusCls ?>" style="font-size:12px;padding:4px 12px"><?= $statusLbl ?></span>
        <div style="flex:1"></div>
        <a href="inventory.php" class="export-btn">← Inventaire</a>
    </div>

    <?php if ($message): ?>
    <div class="<?= $msgType==='error'?'error-box':'success-box' ?>"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">

        <!-- Infos réseau -->
        <div class="panel">
            <div class="panel-header">Informations réseau</div>
            <div class="panel-body">
                <div class="detail-grid">
                    <div class="detail-item"><div class="detail-key">Adresse IP</div><div class="detail-val mono"><?= htmlspecialchars($m['ip']) ?></div></div>
                    <div class="detail-item"><div class="detail-key">Adresse MAC</div><div class="detail-val mono"><?= htmlspecialchars($m['mac'] ?? '—') ?></div></div>
                    <div class="detail-item"><div class="detail-key">Dernière vue</div><div class="detail-val"><?= timeAgo($m['last_seen']) ?></div></div>
                    <div class="detail-item"><div class="detail-key">Latence ping</div><div class="detail-val mono"><?= $m['last_ping_ms'] !== null ? $m['last_ping_ms'].' ms' : '—' ?></div></div>
                    <div class="detail-item"><div class="detail-key">Port switch</div><div class="detail-val mono" style="color:var(--accent2)"><?= htmlspecialchars($m['switch_port'] ?? '—') ?></div></div>
                    <div class="detail-item"><div class="detail-key">Port brassage</div><div class="detail-val mono" style="color:var(--purple)"><?= htmlspecialchars($m['patch_port'] ?? '—') ?></div></div>
                    <div class="detail-item" style="grid-column:span 2"><div class="detail-key">Ports ouverts</div><div class="detail-val mono" style="color:var(--accent2)"><?= htmlspecialchars($m['open_ports'] ?? '—') ?></div></div>
                </div>
            </div>
        </div>

        <!-- Actions rapides -->
        <div class="panel">
            <div class="panel-header">Diagnostics rapides</div>
            <div class="panel-body" style="display:flex;flex-direction:column;gap:8px">
                <form method="post" style="display:flex;gap:8px;flex-wrap:wrap">
                    <button type="submit" name="diag" value="ping"       class="run-btn" style="flex:1">◎ Ping</button>
                    <button type="submit" name="diag" value="ports"      class="export-btn" style="flex:1">⊞ Scan ports</button>
                    <button type="submit" name="diag" value="traceroute" class="export-btn" style="flex:1">⤳ Traceroute</button>
                    <button type="submit" name="diag" value="dns"        class="export-btn" style="flex:1">⊹ DNS</button>
                    <button type="submit" name="diag" value="nmap_os"    class="export-btn" style="flex:1">⊕ Détecter OS</button>
                </form>
                <div class="muted small">Les résultats sont enregistrés dans la fiche.</div>
            </div>
        </div>

    </div>

    <!-- Résultats diagnostic -->
    <?php if ($diagLines): ?>
    <div class="terminal-wrap">
        <div class="terminal-header">
            <div class="term-dots">
                <div class="term-dot" style="background:#ff5f57"></div>
                <div class="term-dot" style="background:#febc2e"></div>
                <div class="term-dot" style="background:#28c840"></div>
            </div>
            <span class="term-title"><?= htmlspecialchars($diagAction) ?> <?= htmlspecialchars($m['ip']) ?></span>
            <button class="term-copy" onclick="copyOutput()">Copier</button>
        </div>
        <div class="terminal-body" id="terminal-body">
            <?php foreach ($diagLines as $line):
                if ($line === '') { echo '<span class="line"> </span>'; continue; }
                $l = htmlspecialchars($line);
                if (preg_match('/TTL|Réponse|Reply|open/i', $line))       echo "<span class='line ok'>$l</span>";
                elseif (preg_match('/timeout|unreachable|filtered/i', $line)) echo "<span class='line warn'>$l</span>";
                elseif (preg_match('/error|failed|Échec/i', $line))        echo "<span class='line err'>$l</span>";
                else echo "<span class='line muted'>$l</span>";
            endforeach; ?>
            <pre id="raw-output"><?php foreach ($diagLines as $l) echo htmlspecialchars($l)."\n"; ?></pre>
        </div>
    </div>
    <?php endif; ?>

    <!-- Édition fiche -->
    <div class="panel">
        <div class="panel-header">Informations complémentaires</div>
        <div class="panel-body">
            <form method="post" style="display:flex;flex-direction:column;gap:12px">
                <div class="form-group">
                    <label class="form-label">Système d'exploitation</label>
                    <input type="text" name="os" class="form-input" value="<?= htmlspecialchars(normalizeOsLabel($m['os'] ?? '') ?? '') ?>" placeholder="Windows 11 Pro">
                </div>
                <div class="form-group">
                    <label class="form-label">Port switch</label>
                    <input type="text" name="switch_port" class="form-input" value="<?= htmlspecialchars($m['switch_port'] ?? '') ?>" placeholder="port1.0.3">
                </div>
                <div class="form-group">
                    <label class="form-label">Port brassage</label>
                    <input type="text" name="patch_port" class="form-input" value="<?= htmlspecialchars($m['patch_port'] ?? '') ?>" placeholder="B31">
                </div>
                <div class="form-group">
                    <label class="form-label">Commentaire / rôle</label>
                    <textarea name="comment" class="form-textarea"><?= htmlspecialchars($m['comment'] ?? '') ?></textarea>
                </div>
                <div>
                    <button type="submit" name="save" value="1" class="run-btn">Enregistrer</button>
                </div>
            </form>
        </div>
    </div>

</div>
</main>
</div>
<script>
function copyOutput() {
    const raw = document.getElementById('raw-output');
    if (!raw) return;
    navigator.clipboard.writeText(raw.innerText).then(() => {
        const btn = document.querySelector('.term-copy');
        if (btn) { btn.textContent='✓ Copié'; setTimeout(()=>btn.textContent='Copier',1500); }
    });
}
const tb = document.getElementById('terminal-body');
if (tb) tb.scrollTop = tb.scrollHeight;
</script>
</body>
</html>
