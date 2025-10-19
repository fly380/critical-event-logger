<?php
/**
 * Critical Event Logger — helper module
 * Copyright © 2025 Казмірчук Андрій
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if (!defined('ABSPATH')) exit;

/**
 * Виконує ротацію та очищення логів
 * @param bool $force Примусова ротація (для ручового запуску)
 */
function crit_rotate_logs($force = false) {
	$log_dir  = plugin_dir_path(__FILE__) . 'logs/';
	$log_file = $log_dir . 'events.log';

	if (!file_exists($log_file)) {
		@file_put_contents($log_file, '[' . date('Y-m-d H:i:s') . "] [System][init][INFO] Створено новий лог-файл (не існував).\n");
		return;
	}

	$max_size_mb = get_option('crit_log_max_size', 5);   // МБ
	$max_files   = get_option('crit_log_keep_files', 7); // кількість архівів
	$max_days	= get_option('crit_log_max_days', 30);  // днів зберігати записи

	$size_bytes = @filesize($log_file);
	$size_mb	= $size_bytes !== false ? round($size_bytes / (1024 * 1024), 2) : 0;
	$now		= current_time('Y-m-d-His');
	$rotated	= false;

	// === 1) РОТАЦІЯ: якщо перевищено ліміт, або примусово (і файл не порожній) ===
	if ( ($force && $size_bytes > 0) || ($size_mb > $max_size_mb) ) {
		$new_name = $log_dir . 'events-' . $now . '.log';
		// спроба перейменувати; якщо ні — копія + очистка
		if (@rename($log_file, $new_name) === false) {
			@copy($log_file, $new_name);
			@file_put_contents($log_file, '');
		}
		@file_put_contents(
			$log_file,
			'[' . date('Y-m-d H:i:s') . "] [System][auto][INFO] Створено новий лог-файл після ротації.\n",
			FILE_APPEND | LOCK_EX
		);
		$rotated = true;

		// Видалити зайві архіви
		$all = glob($log_dir . 'events-*.log');
		if (is_array($all)) {
			usort($all, function($a, $b) { return filemtime($b) - filemtime($a); });
			$to_delete = array_slice($all, $max_files);
			foreach ($to_delete as $f) @unlink($f);
		}
	}

	// === 2) ОЧИСТКА: видалити рядки старші N днів ===
	$lines = @file($log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
	if ($lines) {
		$limit_ts  = time() - ($max_days * DAY_IN_SECONDS);
		$new_lines = [];
		foreach ($lines as $ln) {
			if (preg_match('/^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]/', $ln, $m)) {
				$ts = strtotime($m[1]);
				if ($ts >= $limit_ts) $new_lines[] = $ln;
			} else {
				// якщо рядок без дати — зберігаємо
				$new_lines[] = $ln;
			}
		}
		@file_put_contents($log_file, implode("\n", $new_lines), LOCK_EX);
	}

	// === 3) СЛУЖБОВЕ ПОВІДОМЛЕННЯ У ЛОГ ===
	if ($rotated) {
		$msg = $force
			? 'Виконано примусову ротацію логів (запущено вручну).'
			: 'Виконано ротацію логів (архів створено).';
	} else {
		$msg = 'Виконано очищення логів (старі записи видалено).';
	}
	@file_put_contents($log_file, '[' . date('Y-m-d H:i:s') . "][System][cron][INFO] $msg\n", FILE_APPEND | LOCK_EX);
}

/**
 * Плануємо виконання через WP-Cron (щодоби)
 */
if (!wp_next_scheduled('crit_daily_log_rotation')) {
	wp_schedule_event(time(), 'daily', 'crit_daily_log_rotation');
}
add_action('crit_daily_log_rotation', 'crit_rotate_logs');

/**
 * Адмін-налаштування
 */
add_action('admin_menu', function() {
	add_submenu_page(
		'critical-event-logs',
		'Ротація логів',
		'Ротація логів',
		'manage_options',
		'critical-log-rotation',
		'crit_log_rotation_settings_page'
	);
});

function crit_log_rotation_settings_page() {
	if (isset($_POST['crit_save_rotation'])) {
		check_admin_referer('crit_log_rotation_save', 'crit_log_rotation_nonce');
		update_option('crit_log_max_size',  max(1, intval($_POST['crit_log_max_size'])));
		update_option('crit_log_keep_files',max(1, intval($_POST['crit_log_keep_files'])));
		update_option('crit_log_max_days',  max(1, intval($_POST['crit_log_max_days'])));
		echo '<div class="notice notice-success"><p>✅ Налаштування збережено.</p></div>';
	}

	$size  = get_option('crit_log_max_size', 5);
	$files = get_option('crit_log_keep_files', 7);
	$days  = get_option('crit_log_max_days', 30);

	echo '<div class="wrap"><h1>🗂️ Ротація логів</h1>';
	echo '<form method="post">';
	wp_nonce_field('crit_log_rotation_save', 'crit_log_rotation_nonce');
	echo '<p><label>📦 Максимальний розмір лог-файлу (МБ): <input type="number" name="crit_log_max_size" value="' . esc_attr($size) . '" min="1" max="100" style="width:80px;"></label></p>';
	echo '<p><label>🧾 Зберігати останніх файлів: <input type="number" name="crit_log_keep_files" value="' . esc_attr($files) . '" min="1" max="30" style="width:80px;"></label></p>';
	echo '<p><label>🕐 Видаляти записи старше (днів): <input type="number" name="crit_log_max_days" value="' . esc_attr($days) . '" min="1" max="365" style="width:80px;"></label></p>';
	echo '<p><input type="submit" name="crit_save_rotation" class="button-primary" value="💾 Зберегти"></p>';
	echo '</form>';

	echo '<hr><p style="color:#777;">Ротація виконується автоматично раз на добу через WP-Cron.<br>
	Можна запустити вручну: <a href="?page=critical-log-rotation&crit_run_rotation=1" class="button">🔁 Виконати зараз</a></p>';

	// === Ручний запуск (примусова ротація, якщо файл > 0 байтів) ===
	if (isset($_GET['crit_run_rotation']) && current_user_can('manage_options')) {
		echo '<div class="notice notice-info"><p>🔄 Виконується ротація логів...</p></div>';
		try {
			ob_start();
			crit_rotate_logs(true); // примусовий режим
			ob_end_clean();
			echo '<div class="notice notice-success"><p>✅ Ротацію виконано вручну успішно.</p></div>';
		} catch (Throwable $e) {
			echo '<div class="notice notice-error"><p>❌ Помилка при ротації: ' . esc_html($e->getMessage()) . '</p></div>';
		}
	}

	echo '</div>';
}
