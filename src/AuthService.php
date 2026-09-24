<?php

declare(strict_types=1);

final class AuthService
{
    private const MAX_ATTEMPTS = 5;
    private const WINDOW_SECONDS = 300;
    private const LOCK_SECONDS = 300;
    private const DUMMY_HASH = '$2y$12$GRb9IvPaIdWgIODuip8/j.4IfzbDcqkvLgxcMa8pYSlk8tz656rGW';

    public function __construct(private UserRepository $users) {}

    /** @return array{ok:bool,reason:string,user:?array{id:int,email:string},locked_until:int} */
    public function attempt(string $email, string $password, int $now): array
    {
        $emailKey = hash('sha256', strtolower(trim($email)));
        $state = $this->users->attemptState($emailKey);

        if ($state['locked_until'] > $now) {
            return ['ok' => false, 'reason' => 'locked', 'user' => null, 'locked_until' => $state['locked_until']];
        }

        $user = $this->users->findByEmail($email);
        $hash = $user['password_hash'] ?? self::DUMMY_HASH;
        $passwordMatches = password_verify($password, $hash);

        if ($user === null || !$passwordMatches) {
            $lockedUntil = $this->users->recordFailure(
                $emailKey, $now, self::MAX_ATTEMPTS, self::WINDOW_SECONDS, self::LOCK_SECONDS
            );
            return [
                'ok' => false,
                'reason' => $lockedUntil > $now ? 'locked' : 'invalid',
                'user' => null,
                'locked_until' => $lockedUntil,
            ];
        }

        $this->users->clearFailures($emailKey);

        if (password_needs_rehash($user['password_hash'], PASSWORD_DEFAULT)) {
            $this->users->updatePasswordHash($user['id'], password_hash($password, PASSWORD_DEFAULT));
        }

        return [
            'ok' => true,
            'reason' => 'authenticated',
            'user' => ['id' => $user['id'], 'email' => $user['email']],
            'locked_until' => 0,
        ];
    }
}
