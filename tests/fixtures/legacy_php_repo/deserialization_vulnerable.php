<?php
/**
 * Session and cache loader - contains unsafe deserialization vulnerabilities.
 */

function restoreUserSession() {
    // Unsafe deserialization of cookie payload - triggers legacy.php.deserialization
    $rawCookie = $_COOKIE['auth_session'];
    $session = unserialize($rawCookie);
    return $session;
}

function loadCachedProfile() {
    // Unsafe deserialization of POST payload - triggers legacy.php.deserialization
    $cacheBlob = $_POST['cached_state'];
    return unserialize($cacheBlob);
}

function unpackLegacyToken($tokenString) {
    // Unserialize without allowed_classes => false - triggers legacy.php.deserialization
    return unserialize($tokenString);
}

function safeLoadProfile($jsonString) {
    // Safe deserialization using allowed_classes => false
    return unserialize($jsonString, ['allowed_classes' => false]);
}
