<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/src/bootstrap.php';

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This command can only run from the CLI.\n");
    exit(1);
}

$email = isset($argv[1]) ? trim((string) $argv[1]) : '';
$password = isset($argv[2]) ? (string) $argv[2] : '';

if ($email === '' || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
    fwrite(STDERR, "Usage: php bin/create-user.php user@example.com 'a-strong-password'\n");
    exit(1);
}

$passwordError = LoginValidator::validateNewPassword($password);
if ($passwordError !== null) {
    fwrite(STDERR, $passwordError . "\n");
    exit(1);
}

try {
    $userId = $userRepository->createUser($email, $password);
    fwrite(STDOUT, sprintf("Created user #%d for %s.\n", $userId, $email));
} catch (PDOException $error) {
    if ((string) $error->getCode() === '23000' || str_contains($error->getMessage(), 'UNIQUE constraint failed')) {
        fwrite(STDERR, "A user with that email already exists.\n");
        exit(1);
    }
    throw $error;
}
