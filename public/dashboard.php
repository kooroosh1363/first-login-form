<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/src/bootstrap.php';
$user = require_authenticated_user();
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="Authenticated dashboard for the Gatehouse secure PHP login demo.">
    <meta name="color-scheme" content="light dark">
    <title>Dashboard — Gatehouse</title>
    <link rel="stylesheet" href="/assets/app.css">
</head>
<body class="dashboard-body">
    <header class="dashboard-header">
        <a class="brand" href="/dashboard.php">
            <span class="brand-mark" aria-hidden="true">G</span>
            <span>Gatehouse</span>
        </a>
        <form method="post" action="/logout.php">
            <input type="hidden" name="_token" value="<?= e(csrf_token()) ?>">
            <button class="secondary-button" type="submit">Sign out</button>
        </form>
    </header>

    <main class="dashboard-shell">
        <section class="dashboard-hero">
            <p class="eyebrow">Authenticated session</p>
            <h1>Access granted.</h1>
            <p>You are signed in as <strong><?= e($user['email']) ?></strong>. The session ID was regenerated after authentication and will expire after 30 minutes of inactivity.</p>
        </section>

        <section class="security-grid" aria-label="Authentication status">
            <article><span>Session</span><strong>Active</strong><p>HttpOnly + SameSite cookie settings and periodic ID rotation.</p></article>
            <article><span>CSRF</span><strong>Verified</strong><p>Sign-in and sign-out both require a session-bound token.</p></article>
            <article><span>Password</span><strong>Hashed</strong><p>Credentials are verified with <code>password_verify()</code>; plaintext is never stored.</p></article>
            <article><span>Throttle</span><strong>Enabled</strong><p>Five failed attempts inside five minutes trigger a temporary lock.</p></article>
        </section>

        <section class="architecture-card">
            <p class="section-index">Request path / 02</p>
            <h2>What happened before this page rendered</h2>
            <ol>
                <li>The POST payload was normalized and validated server-side.</li>
                <li>The CSRF token was compared with the session token.</li>
                <li>The account lookup used a prepared SQLite query.</li>
                <li>The submitted secret was checked with <code>password_verify()</code>.</li>
                <li>The session identifier rotated before authenticated state was stored.</li>
            </ol>
        </section>
    </main>
</body>
</html>
