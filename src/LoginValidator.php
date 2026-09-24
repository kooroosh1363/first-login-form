<?php

declare(strict_types=1);

final class LoginValidator
{
    public const EMAIL_MAX = 254;
    public const PASSWORD_MAX = 4096;

    /** @param array<string, mixed> $input
     *  @return array{email:string,password:string,company:string}
     */
    public static function normalize(array $input): array
    {
        return [
            'email' => trim((string) ($input['email'] ?? '')),
            'password' => (string) ($input['password'] ?? ''),
            'company' => trim((string) ($input['company'] ?? '')),
        ];
    }

    /** @param array{email:string,password:string,company:string} $data
     *  @return array<string, string>
     */
    public static function validate(array $data): array
    {
        $errors = [];

        if ($data['email'] === '') {
            $errors['email'] = 'Please enter your email address.';
        } elseif (self::length($data['email']) > self::EMAIL_MAX || filter_var($data['email'], FILTER_VALIDATE_EMAIL) === false) {
            $errors['email'] = 'Please enter a valid email address.';
        }

        if ($data['password'] === '') {
            $errors['password'] = 'Please enter your password.';
        } elseif (self::length($data['password']) > self::PASSWORD_MAX) {
            $errors['password'] = 'Password is too long.';
        }

        if ($data['company'] !== '') {
            $errors['form'] = 'Unable to process this request.';
        }

        return $errors;
    }

    public static function validateNewPassword(string $password): ?string
    {
        $length = self::length($password);
        if ($length < 12) return 'New passwords must be at least 12 characters.';
        if ($length > 128) return 'New passwords must be 128 characters or fewer.';
        return null;
    }

    private static function length(string $value): int
    {
        return function_exists('mb_strlen') ? mb_strlen($value) : strlen($value);
    }
}
