<?php

declare(strict_types=1);

require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/LoginValidator.php';
require_once __DIR__ . '/UserRepository.php';
require_once __DIR__ . '/AuthService.php';

$isCli = PHP_SAPI === 'cli';

if (!$isCli) {
    $isHttps = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';

    ini_set('session.use_strict_mode', '1');
    session_set_cookie_params([
        'httponly' => true,
        'secure' => $isHttps,
        'samesite' => 'Lax',
        'path' => '/',
    ]);

    if (session_status() !== PHP_SESSION_ACTIVE) session_start();

    header("Content-Security-Policy: default-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    header('Referrer-Policy: no-referrer');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
    header('Cache-Control: no-store');

    if ($isHttps) header('Strict-Transport-Security: max-age=31536000; includeSubDomains');

    refresh_authenticated_session(time());
}

$dbPath = getenv('AUTH_DB_PATH') ?: dirname(__DIR__) . '/storage/auth.sqlite';
$storageDirectory = dirname($dbPath);
if (!is_dir($storageDirectory) && !mkdir($storageDirectory, 0775, true) && !is_dir($storageDirectory)) {
    throw new RuntimeException('Unable to create the storage directory.');
}

$pdo = new PDO('sqlite:' . $dbPath);
$userRepository = new UserRepository($pdo);
$userRepository->migrate();
$authService = new AuthService($userRepository);
