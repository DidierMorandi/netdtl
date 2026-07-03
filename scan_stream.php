<?php
// ============================================================
//  NetDTL v3.0 — scan_stream.php
//  Endpoint SSE (Server-Sent Events) pour le scan nmap
// ============================================================
require_once __DIR__ . '/db.php';
requireAuth();
initDB();

$network  = trim($_GET['network'] ?? DEFAULT_NETWORK);
$doports  = ($_GET['ports'] ?? '0') === '1';
$doOS     = ($_GET['os']    ?? '0') === '1';
$doNbstat = ($_GET['nbstat'] ?? '0') === '1';
$doWmi    = ($_GET['wmi']    ?? '0') === '1';

if (!isValidTarget($network)) {
    echo "data: {\"type\":\"error\",\"msg\":\"Réseau invalide.\"}\n\n";
    exit;
}

// ─── Headers SSE ────────────────────────────────────────────
header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('X-Accel-Buffering: no');
set_time_limit(600);
if (ob_get_level()) ob_end_flush();

function getWmiDescription(string $ip): ?string {
    $psIp = str_replace("'", "''", $ip);
    // Récupère la description Windows via PowerShell/WMI
    $cmd = 'powershell -NonInteractive -Command "'
        . '(Get-WmiObject -ComputerName \'' . $psIp . '\' -Class Win32_OperatingSystem'
        . ' -ErrorAction SilentlyContinue).Description'
        . '"';
    $result = shell_exec($cmd . ' 2>&1');
    if (!$result) return null;
    $result = trim(mb_convert_encoding($result, 'UTF-8', 'CP850'));
    // Si erreur PowerShell ou vide
    if (empty($result) || stripos($result, 'Exception') !== false || stripos($result, 'Error') !== false) return null;
    return $result;
}

function shortHostname(string $hostname): string {
    if (filter_var($hostname, FILTER_VALIDATE_IP)) return $hostname;
    $parts = explode('.', $hostname);
    return $parts[0];
}

function sse(array $data): void {
    echo 'data: ' . json_encode($data, JSON_UNESCAPED_UNICODE) . "\n\n";
    if (ob_get_level()) ob_flush();
    flush();
}

// ─── Requête nbstat sur une IP ──────────────────────────────
// Retourne ['name' => 'PC-XXX', 'group' => 'WORKGROUP', 'user' => 'Jean']
function getNbstat(string $ip): array {
    $lines = runCommand(NMAP_PATH . ' -sU -p 137 --script nbstat ' . escapeshellarg($ip));
    $result = ['name' => null, 'group' => null, 'user' => null, 'type' => null];

    foreach ($lines as $line) {
        // NetBIOS name: PC-BEN-001 <00> UNIQUE
        if (preg_match('/^\s+(.+?)\s+<00>\s+UNIQUE/i', $line, $m)) {
            $name = trim($m[1]);
            if (!preg_match('/^[\x00-\x1f]/', $name)) {
                $result['name'] = $name;
            }
        }
        // Groupe de travail <00> GROUP
        if (preg_match('/^\s+(.+?)\s+<00>\s+GROUP/i', $line, $m)) {
            $result['group'] = trim($m[1]);
        }
        // Utilisateur connecté <03>
        if (preg_match('/^\s+(.+?)\s+<03>\s+UNIQUE/i', $line, $m)) {
            $u = trim($m[1]);
            // Exclure le nom machine (déjà capturé) et les entrées système
            if ($u !== $result['name'] && !preg_match('/^[\x00-\x1f]/', $u)) {
                $result['user'] = $u;
            }
        }
        // Type d'équipement via service
        if (preg_match('/Printer|CUPS|print/i', $line))   $result['type'] = 'Imprimante';
        if (preg_match('/Workstation/i', $line))           $result['type'] = $result['type'] ?? 'PC';
        if (preg_match('/Server Service/i', $line))        $result['type'] = $result['type'] ?? 'Serveur';
    }
    return $result;
}

// ─── Construction commande nmap ─────────────────────────────
if ($doOS) {
    $cmd = NMAP_PATH . ' -sS -O --osscan-guess --host-timeout 15s -T4';
} else {
    $cmd = NMAP_PATH . ' -sn --host-timeout 5s -T4';
}
$cmd .= ' -R ' . escapeshellarg($network) . ' 2>&1';

sse(['type' => 'start', 'msg' => "Lancement : $cmd"]);

$pdo     = getDB();
$start   = time();
$hostsUp = 0;

$currentHost    = null;
$currentMac     = null;
$currentOS      = null;
$currentLatency = null;

// ─── Lecture ligne par ligne ─────────────────────────────────
$handle = popen($cmd, 'r');
if (!$handle) {
    sse(['type' => 'error', 'msg' => 'Impossible de lancer nmap.']);
    exit;
}

while (!feof($handle)) {
    $raw = fgets($handle, 1024);
    if ($raw === false) break;

    $line = trim(mb_convert_encoding($raw, 'UTF-8', 'CP850'));
    $line = str_replace("\xc3\xbf", '', $line);
    if ($line === '') continue;

    sse(['type' => 'line', 'msg' => $line]);

    // Nouveau hôte
    if (preg_match('/Nmap scan report for (.+)/i', $line, $m)) {
        if ($currentHost) {
            saveMachineStream($pdo, $currentHost, $currentMac, $currentOS, $currentLatency, $doports);
            $hostsUp++;
            sse(['type' => 'host_saved', 'ip' => $currentHost['ip'], 'hostname' => $currentHost['hostname'], 'mac' => $currentMac, 'os' => $currentOS, 'vendor' => $currentHost['vendor'] ?? null]);
        }
        if (preg_match('/^(.+)\s+\((\d+\.\d+\.\d+\.\d+)\)$/', trim($m[1]), $hm)) {
            $currentHost = ['hostname' => shortHostname(trim($hm[1])), 'ip' => $hm[2]];
        } else {
            $ip = trim($m[1]);
            $currentHost = ['hostname' => shortHostname(gethostbyaddr($ip) ?: $ip), 'ip' => $ip];
        }
        $currentMac = null; $currentOS = null; $currentLatency = null;
        $currentHost['vendor'] = null;
    }

    // Latence
    if ($currentHost && preg_match('/Host is up \(([0-9.]+)s latency\)/i', $line, $m)) {
        $currentLatency = (int)round((float)$m[1] * 1000);
    }

    // MAC + fabricant
    if ($currentHost && preg_match('/MAC Address:\s+([\dA-F:]{17})\s+\(([^)]+)\)/i', $line, $m)) {
        $currentMac = strtoupper($m[1]);
        $currentHost['vendor'] = $m[2];
        sse(['type' => 'mac', 'ip' => $currentHost['ip'], 'mac' => $currentMac, 'vendor' => $m[2]]);
    }

    // OS
    if ($currentHost && preg_match('/OS details:\s+(.+)/i', $line, $m)) {
        $currentOS = normalizeOsLabel(trim($m[1]));
        sse(['type' => 'os', 'ip' => $currentHost['ip'], 'os' => $currentOS]);
    }
}
pclose($handle);

// Dernier hôte
if ($currentHost) {
    saveMachineStream($pdo, $currentHost, $currentMac, $currentOS, $currentLatency, $doports);
    $hostsUp++;
    sse(['type' => 'host_saved', 'ip' => $currentHost['ip'], 'hostname' => $currentHost['hostname'], 'mac' => $currentMac, 'os' => $currentOS, 'vendor' => $currentHost['vendor'] ?? null]);
}

// ─── Phase 2 : nbstat sur tous les hôtes découverts ─────────
if ($doNbstat) {
    sse(['type' => 'line', 'msg' => '']);
    sse(['type' => 'line', 'msg' => '── Identification NetBIOS en cours… ──────────────────']);

    $machines = $pdo->query("SELECT id, ip, hostname FROM machines WHERE status='up' ORDER BY ip")->fetchAll();

    foreach ($machines as $machine) {
        sse(['type' => 'line', 'msg' => "nbstat → {$machine['ip']}…"]);

        $nb = getNbstat($machine['ip']);

        // Si on a trouvé un nom NetBIOS et que la machine n'a pas encore de vrai nom
        $newHostname = null;
        if ($nb['name'] && filter_var($machine['hostname'], FILTER_VALIDATE_IP)) {
            $newHostname = $nb['name'];
        }

        // Construit un commentaire enrichi
        $infos = [];
        if ($nb['type'])  $infos[] = $nb['type'];
        if ($nb['group']) $infos[] = 'Groupe: ' . $nb['group'];
        if ($nb['user'])  $infos[] = 'Utilisateur: ' . $nb['user'];
        $comment = implode(' | ', $infos) ?: null;

        // Mise à jour BDD
        if ($newHostname || $comment) {
            $sets = [];
            $params = [];
            if ($newHostname) { $sets[] = 'hostname=?'; $params[] = $newHostname; }
            if ($comment)     { $sets[] = 'comment=IF(comment IS NULL OR comment="", ?, comment)'; $params[] = $comment; }
            $params[] = $machine['id'];
            $pdo->prepare("UPDATE machines SET " . implode(', ', $sets) . " WHERE id=?")
                ->execute($params);
        }

        $label = $nb['name'] ?? '(pas de réponse NetBIOS)';
        $detail = $comment ? " — $comment" : '';
        sse(['type' => 'nbstat', 'ip' => $machine['ip'], 'name' => $nb['name'], 'group' => $nb['group'], 'user' => $nb['user'], 'comment' => $comment]);
        sse(['type' => 'line', 'msg' => "  → {$machine['ip']} : $label$detail"]);
    }
    sse(['type' => 'line', 'msg' => '── Identification NetBIOS terminée ───────────────────']);
}

// ─── Phase 3 : WMI descriptions ────────────────────────────
if ($doWmi) {
    sse(['type' => 'line', 'msg' => '']);
    sse(['type' => 'line', 'msg' => '── Récupération descriptions WMI… ───────────────────']);

    $machines = $pdo->query("SELECT id, ip, hostname FROM machines WHERE status='up' ORDER BY ip")->fetchAll();

    foreach ($machines as $machine) {
        sse(['type' => 'line', 'msg' => "WMI → {$machine['ip']}…"]);

        $desc = getWmiDescription($machine['ip']);

        if ($desc) {
            $pdo->prepare("UPDATE machines SET comment = ? WHERE id = ? AND (comment IS NULL OR comment = '')")
                ->execute([$desc, $machine['id']]);
            sse(['type' => 'wmi', 'ip' => $machine['ip'], 'desc' => $desc]);
            sse(['type' => 'line', 'msg' => "  → {$machine['ip']} : $desc"]);
        } else {
            sse(['type' => 'line', 'msg' => "  → {$machine['ip']} : (pas de réponse WMI)"]);
        }
    }
    sse(['type' => 'line', 'msg' => '── Descriptions WMI terminées ────────────────────────']);
}

$duration = time() - $start;

$pdo->prepare("INSERT INTO scan_history (network, hosts_up, hosts_down, duration_s) VALUES (?,?,?,?)")
    ->execute([$network, $hostsUp, 0, $duration]);

sse(['type' => 'done', 'hosts' => $hostsUp, 'duration' => $duration]);

// ─── Sauvegarde machine ─────────────────────────────────────
function saveMachineStream(PDO $pdo, array $host, ?string $mac, ?string $os, ?int $latencyMs, bool $doports): void {
    $vendor = $host['vendor'] ?? null;
    $status = 'up';
    $pingMs = $latencyMs;

    $openPorts = null;
    if ($doports) {
        $portLines = runCommand(NMAP_PATH . ' -p 22,80,443,3389,8080,445,21,23,25,3306,5900 --open -T4 ' . escapeshellarg($host['ip']));
        $ports = [];
        foreach ($portLines as $l) {
            if (preg_match('/^(\d+)\/(tcp|udp)\s+open\s+(\S+)/i', $l, $pm)) {
                $ports[] = $pm[1].'/'.$pm[3];
            }
        }
        $openPorts = implode(', ', $ports) ?: null;
    }

    $pdo->prepare("
        INSERT INTO machines (hostname, ip, mac, vendor, os, status, open_ports, last_ping_ms, last_seen)
        VALUES (:hostname, :ip, :mac, :vendor, :os, :status, :open_ports, :ping_ms, NOW())
        ON DUPLICATE KEY UPDATE
            hostname    = VALUES(hostname),
            mac         = COALESCE(VALUES(mac), mac),
            vendor      = COALESCE(VALUES(vendor), vendor),
            os          = COALESCE(VALUES(os), os),
            status      = VALUES(status),
            open_ports  = COALESCE(VALUES(open_ports), open_ports),
            last_ping_ms= VALUES(last_ping_ms),
            last_seen   = NOW()
    ")->execute([
        ':vendor'     => $vendor,
        ':hostname'   => $host['hostname'],
        ':ip'         => $host['ip'],
        ':mac'        => $mac,
        ':os'         => normalizeOsLabel($os),
        ':status'     => $status,
        ':open_ports' => $openPorts,
        ':ping_ms'    => $pingMs,
    ]);
}
