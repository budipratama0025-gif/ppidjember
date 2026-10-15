
<?php
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

require_once __DIR__ . '/../engine/configdb.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_POST['btn-login'])) {
    http_response_code(405);
    exit('Permintaan tidak diizinkan.');
}

$username = trim((string)($_POST['username'] ?? ''));
$userPassword = (string)($_POST['password'] ?? '');

if ($username === '' || $userPassword === '') {
    http_response_code(400);
    exit('Nama pengguna dan kata sandi wajib diisi.');
}

try {
    $stmt = $db_con->prepare(
        'SELECT user.USERID, user.USERNAME, user.USER_PASSWORD,
                skpd.STATUS
         FROM user
         INNER JOIN skpd ON user.IDSKPD = skpd.IDSKPD
         WHERE user.USERNAME = :name
         LIMIT 1'
    );

    $stmt->execute([':name' => $username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    $storedPassword = (string)($row['USER_PASSWORD'] ?? '');
    $isHash = $storedPassword !== ''
        && password_get_info($storedPassword)['algo'] !== null;

    $passwordValid = $isHash
        ? password_verify($userPassword, $storedPassword)
        : hash_equals($storedPassword, base64_encode($userPassword));

    if (
        !$row ||
        !$passwordValid ||
        ($row['STATUS'] ?? '') !== 'AKTIF'
    ) {
        http_response_code(401);
        exit('Nama pengguna atau kata sandi salah, atau unit kerja tidak aktif.');
    }

    if (!session_regenerate_id(true)) {
        http_response_code(500);
        exit('Login gagal. Silakan coba kembali.');
    }

    $_SESSION['USER_SESSION'] = $row['USERID'];

    echo 'TRUE';

} catch (Throwable $e) {
    error_log('PPID login error: ' . $e->getMessage());
    http_response_code(500);
    exit('Terjadi gangguan sistem. Silakan coba kembali.');
}
?>
