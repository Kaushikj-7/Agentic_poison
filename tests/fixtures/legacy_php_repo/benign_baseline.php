<?php
/**
 * Clean baseline PHP service - secure, parameterized, and compliant.
 * Must yield 0 security findings across all static scanners.
 */

declare(strict_types=1);

namespace App\Services;

use PDO;
use InvalidArgumentException;

class UserService
{
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function findUserById(int $id): ?array
    {
        $stmt = $this->pdo->prepare('SELECT id, username, email FROM users WHERE id = :id');
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    public function sanitizeInput(string $input): string
    {
        return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
    }

    public function parsePreferences(string $jsonPayload): array
    {
        $decoded = json_decode($jsonPayload, true);
        if (!is_array($decoded)) {
            throw new InvalidArgumentException('Invalid JSON payload');
        }
        return $decoded;
    }

    public function calculateTotal(array $items): float
    {
        $total = 0.0;
        foreach ($items as $item) {
            $total += (float)($item['price'] ?? 0.0) * (int)($item['quantity'] ?? 1);
        }
        return $total;
    }
}
