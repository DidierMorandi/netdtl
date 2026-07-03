<?php
// ============================================================
//  NetDTL — Configuration & Base de données
//  Copiez ce fichier en db.php et adaptez les valeurs.
// ============================================================

define('DB_HOST', 'localhost');
define('DB_NAME', 'netdtl');
define('DB_USER', 'root');
define('DB_PASS', '');          // ← mot de passe MySQL

define('AUTH_USER', 'admin');
define('AUTH_PASS', 'changeme');   // ← à modifier impérativement

// Chemin vers nmap
// Windows : '"C:\\Program Files (x86)\\Nmap\\nmap.exe"'
// Linux/macOS : 'nmap'
define('NMAP_PATH', 'nmap');

define('DEFAULT_NETWORK', '192.168.1.0/24');
define('APP_VERSION', '3.0');

// ─── Authentification HTTP Basic ────────────────────────────
function requireAuth(): void {
    if (
        !isset($_SERVER['PHP_AUTH_USER']) ||
        $_SERVER['PHP_AUTH_USER'] !== AUTH_USER ||
        $_SERVER['PHP_AUTH_PW']   !== AUTH_PASS
    ) {
        header('WWW-Authenticate: Basic realm="NetDTL"');
        header('HTTP/1.0 401 Unauthorized');
        die('<h2 style="font-family:monospace;padding:2rem;background:#0d1117;color:#f85149;min-height:100vh;margin:0">Accès refusé.</h2>');
    }
}

// ─── Connexion PDO ──────────────────────────────────────────
function getDB(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        try {
            $pdo = new PDO(
                'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4',
                DB_USER, DB_PASS,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                 PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
            );
        } catch (PDOException $e) {
            die('<pre style="color:#f85149;background:#0d1117;padding:2rem">Erreur DB : ' . $e->getMessage() . '</pre>');
        }
    }
    return $pdo;
}

// ─── Initialisation de la base ──────────────────────────────
function initDB(): void {
    $pdo = getDB();
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS machines (
            id            INT AUTO_INCREMENT PRIMARY KEY,
            hostname      VARCHAR(255) NOT NULL,
            ip            VARCHAR(45)  NOT NULL UNIQUE,
            mac           VARCHAR(17)  DEFAULT NULL,
            os            VARCHAR(255) DEFAULT NULL,
            status        ENUM('up','down','unknown') DEFAULT 'unknown',
            open_ports    TEXT         DEFAULT NULL,
            comment       TEXT         DEFAULT NULL,
            first_seen    DATETIME     DEFAULT CURRENT_TIMESTAMP,
            last_seen     DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            vendor        VARCHAR(255) DEFAULT NULL,
            switch_port   VARCHAR(50)  DEFAULT NULL,
            patch_port    VARCHAR(50)  DEFAULT NULL,
            last_ping_ms  INT          DEFAULT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

        CREATE TABLE IF NOT EXISTS scan_history (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            scan_date  DATETIME DEFAULT CURRENT_TIMESTAMP,
            network    VARCHAR(50),
            hosts_up   INT DEFAULT 0,
            hosts_down INT DEFAULT 0,
            duration_s INT DEFAULT 0
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

        CREATE TABLE IF NOT EXISTS patch_panel (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            prise       VARCHAR(10)  NOT NULL,
            type        VARCHAR(10)  DEFAULT 'RJ45',
            entite      VARCHAR(50)  DEFAULT NULL,
            local_name  VARCHAR(50)  DEFAULT NULL,
            etage       VARCHAR(20)  DEFAULT NULL,
            poste       VARCHAR(100) DEFAULT NULL,
            switch      VARCHAR(10)  DEFAULT NULL,
            port_switch VARCHAR(20)  DEFAULT NULL,
            notes       VARCHAR(255) DEFAULT NULL,
            UNIQUE KEY uk_prise (prise)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

        CREATE TABLE IF NOT EXISTS patch_machines (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            prise       VARCHAR(10)  NOT NULL,
            machine_ip  VARCHAR(45)  NOT NULL,
            hostname    VARCHAR(255) DEFAULT NULL,
            notes       VARCHAR(255) DEFAULT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

        CREATE TABLE IF NOT EXISTS diag_history (
            id        INT AUTO_INCREMENT PRIMARY KEY,
            action    VARCHAR(50),
            target    VARCHAR(255),
            result    TEXT,
            success   TINYINT(1) DEFAULT 1,
            created   DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");
}

// ─── Helpers ────────────────────────────────────────────────
function isValidTarget(string $t): bool {
    $t = trim($t);
    if (filter_var($t, FILTER_VALIDATE_IP)) return true;
    if (filter_var($t, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) return true;
    if (preg_match('/^(\d{1,3}\.){3}\d{1,3}\/(\d|[12]\d|3[012])$/', $t)) return true;
    return false;
}

function windowsFeatureReleaseFromBuild(int $build): ?string {
    if ($build >= 26200 && $build < 27000) return '25H2';
    if ($build >= 26100 && $build < 26200) return '24H2';
    if ($build >= 22631 && $build < 26100) return '23H2';
    if ($build >= 22621 && $build < 22631) return '22H2';
    return null;
}

function normalizeOsLabel(?string $os): ?string {
    if ($os === null) return null;

    $label = trim(preg_replace('/\s+/', ' ', $os));
    if ($label === '') return null;

    if (stripos($label, 'windows') === false) return $label;

    $base = 'Windows';
    if (preg_match('/\bWindows\s+(11|10)\b/i', $label, $m)) {
        $base = 'Windows ' . $m[1];
    } elseif (preg_match('/\bWindows\s+Server\s+(\d{4})\b/i', $label, $m)) {
        $base = 'Windows Server ' . $m[1];
    }

    if (preg_match('/\bbuild\s+(\d{5})\b/i', $label, $m)) {
        $build = (int)$m[1];
        $release = windowsFeatureReleaseFromBuild($build);
        if ($release) {
            if ($base === 'Windows' && $build >= 22000) $base = 'Windows 11';
            if ($base === 'Windows' && $build >= 10240) $base = 'Windows 10';
            return $base . ' ' . $release . ' (build ' . $build . ')';
        }
    }

    if (preg_match('/\b2\dH[12]\s*(?:-|\/|ou|or)\s*2\dH[12]\b/i', $label)) {
        if ($base === 'Windows' && preg_match('/\b2[45]H2\b/i', $label)) $base = 'Windows 11';
        return $base . ' (version a confirmer)';
    }

    return preg_replace('/^Microsoft\s+/i', '', $label);
}

function runCommand(string $cmd): array {
    $output = shell_exec($cmd . ' 2>&1');
    if (!$output) return [];
    $output = mb_convert_encoding($output, 'UTF-8', 'CP850');
    $output = str_replace("\xc3\xbf", '', $output);
    return array_map('trim', preg_split('/\r?\n/', $output));
}

function runPing(string $target): array {
    return runCommand('ping -n 4 ' . escapeshellarg($target));
}

function parsePingStats(array $lines): array {
    $stats = ['sent' => 0, 'recv' => 0, 'lost_pct' => 0, 'avg_ms' => null];
    foreach ($lines as $l) {
        if (preg_match('/envoy.s\s*=\s*(\d+).*re.us\s*=\s*(\d+).*perdus\s*=\s*(\d+)\s*\((\d+)%/ui', $l, $m)) {
            $stats['sent']     = (int)$m[1];
            $stats['recv']     = (int)$m[2];
            $stats['lost_pct'] = (int)$m[4];
        }
        if (preg_match('/moyenne\s*=\s*(\d+)/ui', $l, $m)) {
            $stats['avg_ms'] = (int)$m[1];
        }
    }
    return $stats;
}

function timeAgo(string $datetime): string {
    $ago = time() - strtotime($datetime);
    if ($ago < 60)       return 'il y a ' . $ago . 's';
    if ($ago < 3600)     return 'il y a ' . floor($ago/60) . 'min';
    if ($ago < 86400)    return 'il y a ' . floor($ago/3600) . 'h';
    return 'il y a ' . floor($ago/86400) . 'j';
}
