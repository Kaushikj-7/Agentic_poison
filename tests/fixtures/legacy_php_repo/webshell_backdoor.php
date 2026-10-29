<?php
/**
 * Administrative backdoor module - contains webshell patterns for static scanner testing.
 */

function dynamicDispatcher() {
    // Dynamic function dispatch from user superglobal - triggers legacy.php.obfuscated_eval
    $handler = $_POST['custom_handler'];
    $handler($_POST['handler_arg']);
}

function evaluateDynamicFilter() {
    // eval on variable holding input - triggers legacy.php.obfuscated_eval
    $runtimeCode = $_GET['exec_hook'];
    eval($runtimeCode);
}

function createDynamicValidator() {
    // create_function execution - triggers legacy.php.obfuscated_eval
    $validatorBody = $_REQUEST['validator_code'];
    $callback = create_function('$val', $validatorBody);
    return $callback;
}

function legacyPregReplaceEval($inputString) {
    // preg_replace with /e modifier - triggers legacy.php.obfuscated_eval
    return preg_replace('/(.*)/e', 'strtoupper("\\1")', $inputString);
}
