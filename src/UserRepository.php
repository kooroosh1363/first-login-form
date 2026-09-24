<?php

declare(strict_types=1);

final class UserRepository
{
    public function __construct(private PDO $pdo)
    {
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    }

    public function migrate(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )'
        );

        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS login_attempts (
                email_key TEXT PRIMARY KEY,
                failures INTEGER NOT NULL,
                first_failed_at INTEGER NOT NULL,
                locked_until INTEGER NOT NULL DEFAULT 0
            )'
        );
    }

    public function createUser(string $email, string $password): int
    {
        $statement = $this->pdo->prepare(
            'INSERT INTO users (email, password_hash) VALUES (:email, :password_hash)'
        );
        $statement->execute([
            ':email' => $email,
            ':password_hash' => password_hash($password, PASSWORD_DEFAULT),
        ]);
        return (int) $this->pdo->lastInsertId();
    }

    /** @return array{id:int,email:string,password_hash:string}|null */
    public function findByEmail(string $email): ?array
    {
        $statement = $this->pdo->prepare(
            'SELECT id, email, password_hash FROM users WHERE email = :email COLLATE NOCASE LIMIT 1'
        );
        $statement->execute([':email' => $email]);
        $row = $statement->fetch();

        if (!is_array($row)) return null;

        return [
            'id' => (int) $row['id'],
            'email' => (string) $row['email'],
            'password_hash' => (string) $row['password_hash'],
        ];
    }

    public function updatePasswordHash(int $userId, string $passwordHash): void
    {
        $statement = $this->pdo->prepare('UPDATE users SET password_hash = :hash WHERE id = :id');
        $statement->execute([':hash' => $passwordHash, ':id' => $userId]);
    }

    /** @return array{failures:int,first_failed_at:int,locked_until:int} */
    public function attemptState(string $emailKey): array
    {
        $statement = $this->pdo->prepare(
            'SELECT failures, first_failed_at, locked_until FROM login_attempts WHERE email_key = :email_key LIMIT 1'
        );
        $statement->execute([':email_key' => $emailKey]);
        $row = $statement->fetch();

        if (!is_array($row)) {
            return ['failures' => 0, 'first_failed_at' => 0, 'locked_until' => 0];
        }

        return [
            'failures' => (int) $row['failures'],
            'first_failed_at' => (int) $row['first_failed_at'],
            'locked_until' => (int) $row['locked_until'],
        ];
    }

    public function recordFailure(string $emailKey, int $now, int $maxAttempts, int $windowSeconds, int $lockSeconds): int
    {
        $state = $this->attemptState($emailKey);

        if ($state['first_failed_at'] === 0 || ($now - $state['first_failed_at']) >= $windowSeconds) {
            $failures = 1;
            $firstFailedAt = $now;
        } else {
            $failures = $state['failures'] + 1;
            $firstFailedAt = $state['first_failed_at'];
        }

        $lockedUntil = $failures >= $maxAttempts ? $now + $lockSeconds : 0;

        $statement = $this->pdo->prepare(
            'INSERT INTO login_attempts (email_key, failures, first_failed_at, locked_until)
             VALUES (:email_key, :failures, :first_failed_at, :locked_until)
             ON CONFLICT(email_key) DO UPDATE SET
                failures = excluded.failures,
                first_failed_at = excluded.first_failed_at,
                locked_until = excluded.locked_until'
        );
        $statement->execute([
            ':email_key' => $emailKey,
            ':failures' => $failures,
            ':first_failed_at' => $firstFailedAt,
            ':locked_until' => $lockedUntil,
        ]);

        return $lockedUntil;
    }

    public function clearFailures(string $emailKey): void
    {
        $statement = $this->pdo->prepare('DELETE FROM login_attempts WHERE email_key = :email_key');
        $statement->execute([':email_key' => $emailKey]);
    }
}
