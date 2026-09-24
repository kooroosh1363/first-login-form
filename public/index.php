<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/src/bootstrap.php';

if (authenticated_user() !== null) {
    redirect('/dashboard.php');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = LoginValidator::normalize($_POST);
    $errors = LoginValidator::validate($data);

    if (!csrf_is_valid($_POST['_token'] ?? null)) {
        $errors['form'] = 'Your session expired. Please try again.';
    }

    if ($errors === []) {
        $result = $authService->attempt($data['email'], $data['password'], time());

        if ($result['ok'] && is_array($result['user'])) {
            sign_in_session($result['user']);
            redirect('/dashboard.php');
        }

        $errors['form'] = $result['reason'] === 'locked'
            ? 'Too many sign-in attempts. Please wait a few minutes and try again.'
            : 'The email or password is incorrect.';
    }

    flash('errors', $errors);
    flash('old_email', $data['email']);
    redirect('/');
}

$errors = pull_flash('errors', []);
$oldEmail = pull_flash('old_email', '');
$notice = pull_flash('notice');

function login_error(array $errors, string $field): ?string
{
    return isset($errors[$field]) && is_string($errors[$field]) ? $errors[$field] : null;
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="A secure PHP authentication demo with password hashing, CSRF protection, sessions, SQLite, and login throttling.">
    <meta name="color-scheme" content="light dark">
    <title>Gatehouse — Secure PHP Authentication</title>
    <link rel="stylesheet" href="/assets/app.css">
</head>
<body>
    <a class="skip-link" href="#login-form">Skip to sign in</a>

    <main class="auth-shell">
        <section class="story-panel" aria-labelledby="story-title">
            <a class="brand" href="/" aria-label="Gatehouse home">
                <span class="brand-mark" aria-hidden="true">G</span>
                <span>Gatehouse</span>
            </a>

            <div class="story-copy">
                <p class="eyebrow">Secure authentication fundamentals</p>
                <h1 id="story-title">A login form should do more than look secure.</h1>
                <p>Gatehouse turns the original 2023 static design exercise into a real server-side authentication flow with password hashing, session hardening, CSRF protection, and throttled login attempts.</p>
            </div>

            <ul class="security-list" aria-label="Security features">
                <li><span>01</span><div><strong>Passwords stay hashed</strong><small>PHP's password API handles storage and verification.</small></div></li>
                <li><span>02</span><div><strong>Sessions rotate</strong><small>IDs regenerate after authentication and during long sessions.</small></div></li>
                <li><span>03</span><div><strong>Requests are verified</strong><small>CSRF tokens protect sign-in and sign-out actions.</small></div></li>
                <li><span>04</span><div><strong>Failures are throttled</strong><small>Repeated attempts trigger a temporary lock window.</small></div></li>
            </ul>
        </section>

        <section class="form-panel" aria-labelledby="login-title">
            <div class="form-wrap">
                <p class="section-index">Account access / 01</p>
                <h2 id="login-title">Sign in</h2>
                <p class="form-intro">Use a locally provisioned account. This demo intentionally has no public registration or password-recovery flow.</p>

                <?php if (is_string($notice) && $notice !== ''): ?>
                    <div class="notice notice--info" role="status"><?= e($notice) ?></div>
                <?php endif; ?>

                <?php if (($errors['form'] ?? null) !== null): ?>
                    <div class="notice notice--error" role="alert"><?= e((string) $errors['form']) ?></div>
                <?php endif; ?>

                <form id="login-form" method="post" action="/" novalidate>
                    <input type="hidden" name="_token" value="<?= e(csrf_token()) ?>">

                    <div class="honeypot" aria-hidden="true">
                        <label for="company">Company</label>
                        <input id="company" name="company" type="text" tabindex="-1" autocomplete="off">
                    </div>

                    <div class="field">
                        <label for="email">Email</label>
                        <input id="email" name="email" type="email" maxlength="254" autocomplete="username" required
                            value="<?= e(is_string($oldEmail) ? $oldEmail : '') ?>"
                            <?= login_error($errors, 'email') ? 'aria-invalid="true" aria-describedby="email-error"' : '' ?>>
                        <?php if ($error = login_error($errors, 'email')): ?>
                            <p class="field-error" id="email-error"><?= e($error) ?></p>
                        <?php endif; ?>
                    </div>

                    <div class="field">
                        <div class="label-row">
                            <label for="password">Password</label>
                            <span>Never logged or echoed</span>
                        </div>
                        <input id="password" name="password" type="password" maxlength="4096" autocomplete="current-password" required
                            <?= login_error($errors, 'password') ? 'aria-invalid="true" aria-describedby="password-error"' : '' ?>>
                        <?php if ($error = login_error($errors, 'password')): ?>
                            <p class="field-error" id="password-error"><?= e($error) ?></p>
                        <?php endif; ?>
                    </div>

                    <button class="primary-button" type="submit">Enter dashboard <span aria-hidden="true">→</span></button>
                </form>

                <div class="local-note">
                    <span aria-hidden="true">i</span>
                    <p>Create a demo account from the command line with <code>php bin/create-user.php</code>. No default credentials are committed to the repository.</p>
                </div>
            </div>
        </section>
    </main>
</body>
</html>
