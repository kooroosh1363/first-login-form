<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/src/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit('Method Not Allowed');
}

if (authenticated_user() === null || !csrf_is_valid($_POST['_token'] ?? null)) {
    http_response_code(403);
    exit('Forbidden');
}

sign_out_session();
header('Location: /', true, 303);
exit;
