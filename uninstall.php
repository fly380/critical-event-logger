<?php
/**
 * Uninstall handler for Critical Event Logger
 * Видалення опцій/кронів/транзієнтів і папки логів при видаленні плагіну
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
	exit;
}

/**
 * Видалити опції/крони/транзієнти для поточного сайту
 */
function crit_uninstall_cleanup_site() {
	// Опції плагіна
	delete_option('crit_log_max_size');
	delete_option('crit_log_keep_files');
	delete_option('crit_log_max_days');

	// Транзієнти (м'ютекси/антидубль)
	delete_transient('crit_rotation_lock');
	delete_transient('crit_rotation_recent');

	// Розклад (WP-Cron)
	if (function_exists('wp_clear_scheduled_hook')) {
		wp_clear_scheduled_hook('crit_daily_log_rotation');
	}

	// Файли логів у /wp-content/uploads/critical-event-logger/logs
	crit_uninstall_remove_logs_dir();

	// Легасі: якщо колись логи лежали у папці плагіна /logs — приберемо
	$legacy_dir = dirname(__FILE__) . '/logs';
	crit_uninstall_rrmdir($legacy_dir);
}

/**
 * Безпечно видалити теку логів у uploads
 */
function crit_uninstall_remove_logs_dir() {
	$uploads = function_exists('wp_upload_dir') ? wp_upload_dir(null, false) : null;
	if (empty($uploads) || empty($uploads['basedir'])) {
		return;
	}
	$base = trailingslashit($uploads['basedir']);

	// Цільова тека
	$logs_dir    = $base . 'critical-event-logger/logs';
	$plugin_root = $base . 'critical-event-logger';

	// Додаткові запобіжники: видаляємо лише якщо шлях містить правильний сегмент
	if (strpos($logs_dir, 'critical-event-logger') === false) {
		return;
	}

	crit_uninstall_rrmdir($logs_dir);

	// Спробувати прибрати батьківську теку, якщо порожня
	if (is_dir($plugin_root)) {
		$items = @scandir($plugin_root);
		if (is_array($items) && count(array_diff($items, ['.', '..'])) === 0) {
			@rmdir($plugin_root);
		}
	}
}

/**
 * Рекурсивне видалення теки (якщо існує)
 */
function crit_uninstall_rrmdir($dir) {
	if (!is_string($dir) || $dir === '' || !is_dir($dir)) {
		return;
	}
	// Використовуємо SPL-ітератори; у більшості середовищ вони доступні.
	try {
		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ($it as $fileinfo) {
			$path = $fileinfo->getPathname();
			if ($fileinfo->isDir()) {
				@rmdir($path);
			} else {
				@unlink($path);
			}
		}
		@rmdir($dir);
	} catch (Throwable $e) {
		// Fallback на випадок, якщо SPL недоступний
		crit_uninstall_rrmdir_fallback($dir);
	}
}

/**
 * Fallback-видалення без SPL (на випадок відсутності розширення)
 */
function crit_uninstall_rrmdir_fallback($dir) {
	if (!is_dir($dir)) return;
	$items = @scandir($dir);
	if (!is_array($items)) return;
	foreach ($items as $item) {
		if ($item === '.' || $item === '..') continue;
		$path = $dir . DIRECTORY_SEPARATOR . $item;
		if (is_dir($path)) {
			crit_uninstall_rrmdir_fallback($path);
		} else {
			@unlink($path);
		}
	}
	@rmdir($dir);
}

/**
 * Виконати деінсталяцію:
 * - для Multisite пройдемося по всіх блогах
 * - для звичайного сайту — один раз
 */
if (is_multisite()) {
	global $wpdb;
	$blog_ids = $wpdb->get_col("SELECT blog_id FROM {$wpdb->blogs}");
	if ($blog_ids) {
		$current = get_current_blog_id();
		foreach ($blog_ids as $blog_id) {
			switch_to_blog((int)$blog_id);
			crit_uninstall_cleanup_site();
		}
		switch_to_blog((int)$current);
	}
} else {
	crit_uninstall_cleanup_site();
}
