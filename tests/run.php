<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/src/LoginValidator.php';
require_once dirname(__DIR__) . '/src/UserRepository.php';
require_once dirname(__DIR__) . '/src/AuthService.php';

$tests = [];

function test(string $name, callable $callback): void { global $tests; $tests[] = [$name, $callback]; }
function expect_true(bool $condition, string $message = 'Expected condition to be true.'): void { if (!$condition) throw new RuntimeException($message); }
function expect_same(mixed $expected, mixed $actual, string $message = ''): void {
    if ($expected !== $actual) {
        throw new RuntimeException($message !== '' ? $message : sprintf('Expected %s, got %s.', var_export($expected, true), var_export($actual, true)));
    }
}
function sqlite_repository(): UserRepository {
    expect_true(in_array('sqlite', PDO::getAvailableDrivers(), true), 'pdo_sqlite is required for integration tests.');
    $pdo = new PDO('sqlite::memory:');
    $repository = new UserRepository($pdo);
    $repository->migrate();
    return $repository;
}

test('normalizes email without mutating password', function (): void {
    $data = LoginValidator::normalize(['email' => '  person@example.com  ', 'password' => '  secret with spaces  ']);
    expect_same('person@example.com', $data['email']);
    expect_same('  secret with spaces  ', $data['password']);
});

test('validates login fields and honeypot', function (): void {
    $errors = LoginValidator::validate(LoginValidator::normalize(['email' => 'not-an-email', 'password' => '', 'company' => 'bot']));
    foreach (['email', 'password', 'form'] as $field) expect_true(isset($errors[$field]), "Expected validation error for {$field}.");
});

test('enforces strong provisioning passwords', function (): void {
    expect_true(LoginValidator::validateNewPassword('too-short') !== null);
    expect_same(null, LoginValidator::validateNewPassword('correct-horse-battery-staple'));
});

test('stores a password hash instead of plaintext', function (): void {
    $repository = sqlite_repository();
    $repository->createUser('user@example.com', 'correct-horse-battery-staple');
    $user = $repository->findByEmail('USER@example.com');

    expect_true(is_array($user));
    expect_true($user['password_hash'] !== 'correct-horse-battery-staple');
    expect_true(password_verify('correct-horse-battery-staple', $user['password_hash']));
});

test('authenticates valid credentials and rejects invalid credentials', function (): void {
    $repository = sqlite_repository();
    $repository->createUser('user@example.com', 'correct-horse-battery-staple');
    $auth = new AuthService($repository);

    $bad = $auth->attempt('user@example.com', 'wrong-password', 1000);
    expect_same(false, $bad['ok']);
    expect_same('invalid', $bad['reason']);

    $good = $auth->attempt('user@example.com', 'correct-horse-battery-staple', 1001);
    expect_same(true, $good['ok']);
    expect_same('user@example.com', $good['user']['email']);
});

test('rate limits repeated failures and unlocks after the window', function (): void {
    $repository = sqlite_repository();
    $repository->createUser('user@example.com', 'correct-horse-battery-staple');
    $auth = new AuthService($repository);

    for ($attempt = 1; $attempt <= 5; $attempt++) {
        $result = $auth->attempt('user@example.com', 'wrong-password', 2000 + $attempt);
    }

    expect_same('locked', $result['reason']);
    expect_true($result['locked_until'] > 2005);

    $stillLocked = $auth->attempt('user@example.com', 'correct-horse-battery-staple', 2100);
    expect_same(false, $stillLocked['ok']);
    expect_same('locked', $stillLocked['reason']);

    $afterLock = $auth->attempt('user@example.com', 'correct-horse-battery-staple', 2400);
    expect_same(true, $afterLock['ok']);
});

$failures = 0;
foreach ($tests as [$name, $callback]) {
    try {
        $callback();
        fwrite(STDOUT, "[pass] {$name}\n");
    } catch (Throwable $error) {
        $failures++;
        fwrite(STDERR, "[fail] {$name}: {$error->getMessage()}\n");
    }
}
fwrite(STDOUT, sprintf("\n%d test(s), %d failure(s).\n", count($tests), $failures));
exit($failures === 0 ? 0 : 1);
