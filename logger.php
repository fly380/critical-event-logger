<?php
/**
 * Critical Event Logger — helper module
 * Copyright © 2025 Казмірчук Андрій
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */
defined('ABSPATH') || exit;

/**
 * Основна функція логування повідомлень.
 *
 * @param string $message Повідомлення для запису.
 * @param string $level Рівень логування (INFO, ERROR, WARNING, тощо).
 */
function critical_logger_log($message, $level = 'INFO') {
	$log_dir = plugin_dir_path(__FILE__) . 'logs/';
	$log_file = $log_dir . 'events.log';

	if (!file_exists($log_dir)) {
		mkdir($log_dir, 0755, true);
	}

	$datetime = date('Y-m-d H:i:s');
	$ip = $_SERVER['REMOTE_ADDR'] ?? 'CLI';

	// Отримуємо користувача
	if (function_exists('wp_get_current_user')) {
		$user = wp_get_current_user();
		$username = ($user && $user->exists()) ? $user->user_login : 'guest';
	} else {
		$username = 'unknown';
	}

	// Приводимо рівень до верхнього регістру
	$level = strtoupper($level);
	$log = "[$datetime][$ip][$username][$level] $message\n";

	error_log($log, 3, $log_file);
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
