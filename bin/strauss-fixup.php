<?php

declare(strict_types=1);

/**
 * Prefix namespace string literals that Strauss 0.22.2 leaves untouched.
 *
 * Strauss does not rewrite a literal that ends right after a namespace
 * separator, e.g. 'phpseclib3\Crypt\\' . static::ALGORITHM in phpseclib's
 * AsymmetricKey::loadPlugins(). Left alone, phpseclib looks up unprefixed
 * classes and cannot load any RSA key.
 *
 * Usage: php bin/strauss-fixup.php (run after bin/strauss.phar)
 */

$root = dirname(__DIR__);
$composer = json_decode((string) file_get_contents($root . '/composer.json'), true);
$prefix = rtrim((string) ($composer['extra']['strauss']['namespace_prefix'] ?? ''), '\\');
$target = $root . '/' . trim((string) ($composer['extra']['strauss']['target_directory'] ?? 'vendor-prefixed'), '/');

if ('' === $prefix || ! is_dir($target)) {
    fwrite(STDERR, "strauss-fixup: missing namespace_prefix or {$target}\n");
    exit(1);
}

$pattern = '/([\'"])(phpseclib3|ParagonIE(?:\\\\{1,2})ConstantTime|RobRichards(?:\\\\{1,2})XMLSecLibs)(\\\\{1,2})/';

$fixed = 0;
$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($target, FilesystemIterator::SKIP_DOTS));
foreach ($files as $file) {
    if (! $file instanceof SplFileInfo || 'php' !== $file->getExtension()) {
        continue;
    }
    $path = $file->getPathname();
    $contents = (string) file_get_contents($path);
    $updated = preg_replace_callback(
        $pattern,
        static fn (array $m): string => $m[1] . str_replace('\\', $m[3], $prefix) . $m[3] . $m[2] . $m[3],
        $contents,
        -1,
        $count
    );
    if (null === $updated) {
        fwrite(STDERR, "strauss-fixup: regex failed on {$path}\n");
        exit(1);
    }
    if ($count > 0) {
        file_put_contents($path, $updated);
        $fixed += $count;
        fwrite(STDOUT, "strauss-fixup: prefixed {$count} literal(s) in " . substr($path, strlen($root) + 1) . "\n");
    }
}

fwrite(STDOUT, "strauss-fixup: {$fixed} literal(s) prefixed\n");
