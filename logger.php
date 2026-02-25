<?php
/**
 * Critical Event Logger — helper module
 * Copyright © 2025 Казмірчук Андрій
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */
defined('ABSPATH') || exit;

/**
 * NEW: Centralized logs directory in /wp-content/uploads/critical-event-logger/logs
 * - Ensures directory exists
 * - Auto-generates .htaccess and index.php
 * - Migrates legacy plugin_dir/logs/events.log if present
 */
if (!function_exists('crit_logs_dir')) {
	function crit_logs_dir(): string {
		if (function_exists('wp_upload_dir')) {
			$u = wp_upload_dir();
			$base = trailingslashit($u['basedir']) . 'critical-event-logger/logs/';
		} else {
			// Fallback for early bootstrap: keep old location
			$base = plugin_dir_path(__FILE__) . 'logs/';
		}
		// Ensure dir
		if (!file_exists($base)) {
			wp_mkdir_p($base);
		}
		// Generate .htaccess
		$hta = $base . '.htaccess';
		if (!file_exists($hta)) {
			$hta_content = <<<HTA
# Заборонити прямий доступ до лог-файлів
<FilesMatch "\\.(log|txt)$">
    Order allow,deny
    Deny from all
</FilesMatch>
HTA;
			@file_put_contents($hta, $hta_content, LOCK_EX);
		}
		// Generate index.php
		$idx = $base . 'index.php';
		if (!file_exists($idx)) {
			@file_put_contents($idx, "<?php http_response_code(404); exit;");
		}
		// Migrate old events.log if exists
		$old_dir  = plugin_dir_path(__FILE__) . 'logs/';
		$old_file = $old_dir . 'events.log';
		$new_file = $base . 'events.log';
		if (@file_exists($old_file) && !@file_exists($new_file)) {
			@rename($old_file, $new_file);
		}
		return $base;
	}
}
if (!function_exists('crit_log_file')) {
	function crit_log_file(): string {
		return trailingslashit(crit_logs_dir()) . 'events.log';
	}
}


/**
 * Основна функція логування повідомлень.
 *
 * @param string $message Повідомлення для запису.
 * @param string $level Рівень логування (INFO, ERROR, WARNING, тощо).
 */
function critical_logger_log($message, $level = 'INFO') {
	$log_dir = crit_logs_dir();
	$log_file = crit_log_file();

	$datetime = crit_log_time(); // локальний TZ із налаштувань WP
	$ip = function_exists('crit_client_ip') ? crit_client_ip() : ($_SERVER['REMOTE_ADDR'] ?? 'CLI');

	// Отримуємо користувача
	if (function_exists('wp_get_current_user')) {
		$user = wp_get_current_user();
		$username = ($user && $user->exists()) ? $user->user_login : 'guest';
	} else {
		$username = 'unknown';
	}

	// Приводимо рівень до верхнього регістру
	$level = strtoupper($level);
	$log = "[$datetime][$ip][$username][$level] $message";

	// crit_append_log_line використовує LOCK_EX і гарантує перенос рядка —
	// на відміну від error_log() який не блокує файл і може склеювати рядки
	// при паралельних запитах. Якщо функція ще не завантажена (logger.php
	// підключається раніше critical-logger.php) — fallback на file_put_contents з LOCK_EX
	if (function_exists('crit_append_log_line')) {
		crit_append_log_line($log_file, $log);
	} else {
		@file_put_contents($log_file, $log . "\n", FILE_APPEND | LOCK_EX);
	}
}

/**
 * Обробник помилок PHP.
 *
 * @param int $errno
 * @param string $errstr
 * @param string $errfile
 * @param int $errline
 * @return bool
 */
function critical_logger_error_handler($errno, $errstr, $errfile, $errline) {
	if (!(error_reporting() & $errno)) {
		return false;
	}

	$types = [
		E_ERROR			 => 'ERROR',
		E_WARNING		   => 'WARNING',
		E_PARSE			 => 'PARSE ERROR',
		E_NOTICE			=> 'NOTICE',
		E_CORE_ERROR		=> 'CORE ERROR',
		E_CORE_WARNING	  => 'CORE WARNING',
		E_COMPILE_ERROR	 => 'COMPILE ERROR',
		E_COMPILE_WARNING   => 'COMPILE WARNING',
		E_USER_ERROR		=> 'USER ERROR',
	// E_USER_WARNING	  => 'USER WARNING',
		E_USER_NOTICE	   => 'USER NOTICE',
		E_DEPRECATED		=> 'DEPRECATED',
		E_USER_DEPRECATED   => 'USER DEPRECATED',
		E_STRICT			=> 'STRICT',
		E_RECOVERABLE_ERROR => 'RECOVERABLE ERROR',
	];

	$type = $types[$errno] ?? 'UNKNOWN';
	critical_logger_log("PHP $type: $errstr in $errfile on line $errline", $type);
	return false;
}

/**
 * Обробник фатальних помилок (shutdown handler).
 */
function critical_logger_shutdown_handler() {
	$error = error_get_last();
	if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
		critical_logger_log("FATAL ERROR: {$error['message']} in {$error['file']} on line {$error['line']}", 'FATAL');
	}
}
// crit_log_time() визначена у critical-logger.php з повним коментарем.
// logger.php завантажується першим, тому тут лише мінімальний fallback
// на випадок якщо critical-logger.php ще не підключений.
if (!function_exists('crit_log_time')) {
	function crit_log_time(string $format = 'Y-m-d H:i:s'): string {
		return function_exists('wp_date') ? wp_date($format) : date($format);
	}
}