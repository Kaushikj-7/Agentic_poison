<?php
/**
 * Database query module - contains SQL injection vulnerabilities for static scanner testing.
 */

function getUserById($conn, $userId) {
    // Direct concatenation in query call - triggers legacy.php.sqli
    $sql = "SELECT id, username, email FROM users WHERE id = '" . $_GET['user_id'] . "'";
    $result = mysqli_query($conn, $sql);
    return mysqli_fetch_assoc($result);
}

function searchOrders($db) {
    // Dynamic query string assignment with user input - triggers legacy.php.sqli
    $query = "SELECT * FROM orders WHERE customer_name = '" . $_POST['customer'] . "' AND status = 'pending'";
    return $db->query($query);
}

function getProductCatalog($pdo) {
    // Direct interpolation in PDO query call - triggers legacy.php.sqli
    $stmt = $pdo->query("SELECT * FROM products WHERE category = '" . $_REQUEST['category'] . "'");
    return $stmt->fetchAll();
}
