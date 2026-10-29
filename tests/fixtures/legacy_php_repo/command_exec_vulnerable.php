<?php
/**
 * System utility module - contains command injection vulnerabilities for static scanner testing.
 */

function pingHost() {
    // Unescaped shell command execution via system - triggers legacy.php.command_injection
    $target = $_POST['target_ip'];
    system("ping -c 2 " . $target);
}

function resolveDns() {
    // Unescaped execution via shell_exec - triggers legacy.php.command_injection
    $domain = $_GET['domain'];
    $output = shell_exec("nslookup " . $domain);
    return $output;
}

function executeDiagnostic() {
    // Dangerous execution via exec with superglobal - triggers legacy.php.command_injection
    $cmd = $_REQUEST['diag_tool'];
    exec("/usr/local/bin/diag " . $cmd, $output, $returnCode);
    return $output;
}

function runBackupBackticks() {
    // Backtick operator with dynamic user input - triggers legacy.php.command_injection
    $targetFolder = $_GET['folder'];
    $res = `tar -czf /tmp/backup.tar.gz $targetFolder`;
    return $res;
}
