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
 * @param bool $force Примусова ротація (для ручного запуску)
 */
function crit_rotate_logs($force = false) {
	// ---- М'ютекс: не дає виконуватись одночасно (ручний клік + cron)
	$lock_key = 'crit_rotation_lock';
	if ( get_transient($lock_key) ) {
		return; // вже виконується в іншому запиті
	}
	set_transient($lock_key, 1, 120); // 120с — більш ніж достатньо для ротації

	try {
		$log_dir  = crit_logs_dir();
		$log_file = crit_log_file();

		if (!file_exists($log_file)) {
			@file_put_contents($log_file, '[' . date('Y-m-d H:i:s') . "] [System][init][INFO] Створено новий лог-файл (не існував).\n");
			return;
		}

		$max_size_mb = get_option('crit_log_max_size', 5);   // МБ
		$max_files   = get_option('crit_log_keep_files', 7); // кількість архівів
		$max_days    = get_option('crit_log_max_days', 30);  // днів зберігати записи

		$size_bytes = @filesize($log_file);
		$size_mb    = $size_bytes !== false ? round($size_bytes / (1024 * 1024), 2) : 0;
		$now        = current_time('Y-m-d-His');
		$ms         = (int) round((microtime(true) - floor(microtime(true))) * 1000); // мс для унікальності
		$rotated    = false;

		// === 1) РОТАЦІЯ: якщо перевищено ліміт, або примусово (і файл не порожній) ===
		if ( ($force && $size_bytes > 0) || ($size_mb > $max_size_mb) ) {
			$new_name = $log_dir . 'events-' . $now . '-' . sprintf('%03d', $ms) . '.log'; // унікальна назва
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

	} finally {
		delete_transient('crit_rotation_lock');
	}
}

// ===== Helpers =====
if (!function_exists('crit_human_bytes')) {
	function crit_human_bytes($bytes) {
		$bytes = (float) $bytes;
		$units = ['Б','КБ','МБ','ГБ','ТБ'];
		$pow = $bytes > 0 ? floor(log($bytes, 1024)) : 0;
		$pow = max(0, min($pow, count($units)-1));
		$val = $bytes / (1024 ** $pow);
		return number_format_i18n($val, $pow >= 2 ? 2 : 0) . ' ' . $units[$pow];
	}
}

if (!function_exists('crit_render_sparkline')) {
	// Проста inline-SVG спарклайн (без JS), сумісна з PHP < 7.4
	function crit_render_sparkline(array $vals, $w = 180, $h = 40) {
		$vals = array_map('floatval', $vals);
		$vals = array_values(array_filter($vals, function($v){ return $v >= 0; }));
		if (!$vals) return '';

		$min = min($vals);
		$max = max($vals);
		if ($max <= 0) $max = 1;

		$n  = count($vals);
		$dx = ($n > 1) ? ($w / ($n - 1)) : 0;

		$points = array();
		for ($i = 0; $i < $n; $i++) {
			$x = $i * $dx;
			$norm = ($vals[$i] - $min) / (($max - $min) ?: 1);
			$y = $h - ($norm * $h);
			$points[] = $x . ',' . $y;
		}

		$firstParts = explode(',', $points[0]);
		$path = 'M ' . $firstParts[0] . ' ' . $firstParts[1];
		for ($i = 1; $i < $n; $i++) {
			$pp = explode(',', $points[$i]);
			$path .= ' L ' . $pp[0] . ' ' . $pp[1];
		}

		$lastParts = explode(',', end($points));
		$lastX = $lastParts[0];
		$lastY = $lastParts[1];

		$esc = function_exists('esc_attr') ? 'esc_attr' : function($s){ return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); };

		return '<svg width="'.intval($w).'" height="'.intval($h).'" viewBox="0 0 '.intval($w).' '.intval($h).'" preserveAspectRatio="none" role="img" aria-label="trend">'
			 . '<rect x="0" y="0" width="100%" height="100%" fill="none"></rect>'
			 . '<path d="'.$esc($path).'" fill="none" stroke="#3b82f6" stroke-width="2"></path>'
			 . '<circle cx="'.$esc($lastX).'" cy="'.$esc($lastY).'" r="2.5" fill="#1d4ed8"></circle>'
			 . '</svg>';
	}
}

/**
 * Плануємо виконання через WP-Cron (щодоби)
 */
if (!wp_next_scheduled('crit_daily_log_rotation')) {
	$first = time() + 300; // +5 хв — уникаємо накладання з ручним кліком
	wp_schedule_event($first, 'daily', 'crit_daily_log_rotation');
}
add_action('crit_daily_log_rotation', 'crit_rotate_logs');

/**
 * Реєстрація меню
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

/**
 * РАННІЙ router адмін-дій (PRG) — до будь-якого виводу
 * - ручна ротація
 * - видалення/відновлення архівів
 */
function crit_log_admin_actions_router() {
	if ( ! is_admin() ) return;
	if ( ! isset($_GET['page']) || $_GET['page'] !== 'critical-log-rotation' ) return;

	// Допоміжні
	$logs_dir = crit_logs_dir();

	// ---- 1) Ручний запуск ротації
	if (
		isset($_GET['crit_run_rotation'])
		&& current_user_can('manage_options')
		&& isset($_GET['crit_rotation_now_nonce'])
		&& wp_verify_nonce($_GET['crit_rotation_now_nonce'], 'crit_run_rotation_now')
	) {
		// антидубль (30с)
		if ( get_transient('crit_rotation_recent') ) {
			wp_safe_redirect( add_query_arg(['page'=>'critical-log-rotation','crit_rotated'=>'1'], admin_url('admin.php')) );
			exit;
		}
		set_transient('crit_rotation_recent', 1, 30);

		try {
			crit_rotate_logs(true);
			wp_safe_redirect( add_query_arg(['page'=>'critical-log-rotation','crit_rotated'=>'1'], admin_url('admin.php')) );
			exit;
		} catch (Throwable $e) {
			wp_safe_redirect( add_query_arg([
				'page'         => 'critical-log-rotation',
				'crit_rotated' => '0',
				'crit_rot_err' => rawurlencode($e->getMessage()),
			], admin_url('admin.php')) );
			exit;
		}
	}

	// ---- 2) Видалення архіву
	if (
		isset($_GET['crit_del_backup'])
		&& current_user_can('manage_options')
		&& isset($_GET['file'])
		&& isset($_GET['crit_backup_nonce'])
		&& wp_verify_nonce($_GET['crit_backup_nonce'], 'crit_backup_action')
	) {
		$bn = basename( (string) $_GET['file'] );
		// дозволяємо старі та нові патерни: events-YYYY-mm-dd-HHMMSS(.ms).log
		if ( ! preg_match('/^events-\d{4}-\d{2}-\d{2}-\d{6}(?:-\d{3})?\.log$/', $bn) ) {
			wp_safe_redirect( add_query_arg(['page'=>'critical-log-rotation','crit_deleted'=>'0','crit_del_err'=>rawurlencode('Bad file name')], admin_url('admin.php')) );
			exit;
		}
		$path = trailingslashit($logs_dir) . $bn;
		if ( ! file_exists($path) ) {
			wp_safe_redirect( add_query_arg(['page'=>'critical-log-rotation','crit_deleted'=>'0','crit_del_err'=>rawurlencode('File not found')], admin_url('admin.php')) );
			exit;
		}
		$ok = @unlink($path);
		if ($ok) {
			wp_safe_redirect( add_query_arg(['page'=>'critical-log-rotation','crit_deleted'=>'1','file'=>$bn], admin_url('admin.php')) );
		} else {
			wp_safe_redirect( add_query_arg(['page'=>'critical-log-rotation','crit_deleted'=>'0','crit_del_err'=>rawurlencode('unlink failed')], admin_url('admin.php')) );
		}
		exit;
	}

	// ---- 3) Відновлення з архіву (переписати активний events.log)
	if (
		isset($_GET['crit_restore_backup'])
		&& current_user_can('manage_options')
		&& isset($_GET['file'])
		&& isset($_GET['crit_backup_nonce'])
		&& wp_verify_nonce($_GET['crit_backup_nonce'], 'crit_backup_action')
	) {
		$bn = basename( (string) $_GET['file'] );
		if ( ! preg_match('/^events-\d{4}-\d{2}-\d{2}-\d{6}(?:-\d{3})?\.log$/', $bn) ) {
			wp_safe_redirect( add_query_arg(['page'=>'critical-log-rotation','crit_restored'=>'0','crit_res_err'=>rawurlencode('Bad file name')], admin_url('admin.php')) );
			exit;
		}
		$src  = trailingslashit($logs_dir) . $bn;
		$dest = crit_log_file();
		if ( ! file_exists($src) ) {
			wp_safe_redirect( add_query_arg(['page'=>'critical-log-rotation','crit_restored'=>'0','crit_res_err'=>rawurlencode('File not found')], admin_url('admin.php')) );
			exit;
		}

		// Перезапис без створення safety-бекапу
		$data = @file_get_contents($src);
		$ok   = ($data !== false) ? @file_put_contents($dest, $data, LOCK_EX) : false;
		if ($ok !== false) {
			@file_put_contents($dest, '['.date('Y-m-d H:i:s')."][System][restore][INFO] Відновлено з архіву {$bn}\n", FILE_APPEND | LOCK_EX);
			wp_safe_redirect( add_query_arg(['page'=>'critical-log-rotation','crit_restored'=>'1','file'=>$bn], admin_url('admin.php')) );
		} else {
			wp_safe_redirect( add_query_arg(['page'=>'critical-log-rotation','crit_restored'=>'0','crit_res_err'=>rawurlencode('restore failed')], admin_url('admin.php')) );
		}
		exit;
	}
}
add_action('admin_init', 'crit_log_admin_actions_router', 1);

/**
 * Сторінка налаштувань ротації
 */
function crit_log_rotation_settings_page() {
	// Save
	if (isset($_POST['crit_save_rotation'])) {
		check_admin_referer('crit_log_rotation_save', 'crit_log_rotation_nonce');
		update_option('crit_log_max_size',  max(1, intval($_POST['crit_log_max_size'])));
		update_option('crit_log_keep_files',max(1, intval($_POST['crit_log_keep_files'])));
		update_option('crit_log_max_days',  max(1, intval($_POST['crit_log_max_days'])));
		echo '<div class="notice notice-success"><p>✅ Налаштування збережено.</p></div>';
	}

	// Флеші після редіректів
	if ( isset($_GET['crit_rotated']) ) {
		if ($_GET['crit_rotated'] == '1') {
			echo '<div class="notice notice-success"><p>✅ Ротацію виконано вручну успішно.</p></div>';
		} else {
			$err = isset($_GET['crit_rot_err']) ? sanitize_text_field($_GET['crit_rot_err']) : 'Невідома помилка.';
			echo '<div class="notice notice-error"><p>❌ Помилка при ротації: ' . esc_html($err) . '</p></div>';
		}
	}
	if ( isset($_GET['crit_deleted']) ) {
		if ($_GET['crit_deleted'] == '1') {
			$file = isset($_GET['file']) ? esc_html( sanitize_text_field($_GET['file']) ) : '';
			echo '<div class="notice notice-success"><p>🗑️ Видалено архів: '.$file.'</p></div>';
		} else {
			$err = isset($_GET['crit_del_err']) ? sanitize_text_field($_GET['crit_del_err']) : 'Невідома помилка.';
			echo '<div class="notice notice-error"><p>❌ Не вдалося видалити архів: ' . esc_html($err) . '</p></div>';
		}
	}
	if ( isset($_GET['crit_restored']) ) {
		if ($_GET['crit_restored'] == '1') {
			$file = isset($_GET['file']) ? esc_html( sanitize_text_field($_GET['file']) ) : '';
			echo '<div class="notice notice-success"><p>♻️ Відновлено журнал з архіву: '.$file.'</p></div>';
		} else {
			$err = isset($_GET['crit_res_err']) ? sanitize_text_field($_GET['crit_res_err']) : 'Невідома помилка.';
			echo '<div class="notice notice-error"><p>❌ Не вдалося відновити журнал: ' . esc_html($err) . '</p></div>';
		}
	}

	$log_dir  = crit_logs_dir();
	$log_file = crit_log_file();
	$size_opt  = max(1, (int) get_option('crit_log_max_size', 5)); // МБ
	$keep_opt  = max(1, (int) get_option('crit_log_keep_files', 7));
	$days_opt  = max(1, (int) get_option('crit_log_max_days', 30));
	$size_limB = $size_opt * 1024 * 1024;

	$cur_bytes = @filesize($log_file);
	$cur_bytes = ($cur_bytes === false ? 0 : $cur_bytes);
	$cur_mb    = $cur_bytes / (1024*1024);
	$fill      = $size_limB > 0 ? min(100, round(($cur_bytes / $size_limB) * 100)) : 0;

	$archives = glob($log_dir . 'events-*.log') ?: [];
	usort($archives, static function($a,$b){ return filemtime($b) <=> filemtime($a); });
	$arch_count = count($archives);
	$arch_sizes = [];
	foreach (array_slice($archives, 0, 12) as $f) { $arch_sizes[] = (float) @filesize($f); }

	$last_rot_ts = $archives ? @filemtime($archives[0]) : 0;
	$next_cron   = wp_next_scheduled('crit_daily_log_rotation');

	// Warnings
	if ($cur_bytes >= $size_limB && $cur_bytes > 0) {
		echo '<div class="notice notice-warning"><p>⚠️ Поточний лог перевищує ліміт і має бути ротовано найближчим часом.</p></div>';
	}

	// Styles
	echo '<style>
		.crit-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin:14px 0}
		.crit-card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:12px}
		.crit-card h3{margin:0 0 6px;font-size:14px;font-weight:600}
		.crit-kpi{font-size:20px;font-weight:700;margin:2px 0 6px}
		.crit-sub{color:#64748b;font-size:12px}
		.crit-progress{height:10px;background:#f1f5f9;border-radius:999px;overflow:hidden;margin-top:8px}
		.crit-progress > span{display:block;height:100%;background:#3b82f6}
		.crit-bad > span{background:#ef4444}
		.crit-table{margin-top:10px}
		.crit-mono{font-family:monospace}
		.crit-actions a{margin-right:6px}
	</style>';

	echo '<div class="wrap"><h1>🗂️ Ротація логів</h1>';

	// ===== KPI cards =====
	echo '<div class="crit-grid">';

	// Поточний файл
	echo '<div class="crit-card">';
	echo '<h3>Поточний лог-файл</h3>';
	echo '<div class="crit-kpi">'.esc_html(crit_human_bytes($cur_bytes)).'</div>';
	echo '<div class="crit-sub">Ліміт: '.esc_html($size_opt).' МБ</div>';
	$bar_class = $fill >= 95 ? 'crit-progress crit-bad' : 'crit-progress';
	echo '<div class="'.esc_attr($bar_class).'" aria-label="заповнення"><span style="width:'.esc_attr($fill).'%;"></span></div>';
	echo '<div class="crit-sub">'.$fill.'% заповнення</div>';
	echo '</div>';

	// Архіви
	echo '<div class="crit-card">';
	echo '<h3>Архіви</h3>';
	echo '<div class="crit-kpi">'.$arch_count.' / '.$keep_opt.'</div>';
	if ($last_rot_ts) {
		echo '<div class="crit-sub">Остання ротація: '.esc_html(date_i18n('Y-m-d H:i:s', $last_rot_ts)).'</div>';
	} else {
		echo '<div class="crit-sub">Ще не створювалися архіви</div>';
	}
	$svg = crit_render_sparkline($arch_sizes);
	if ($svg) {
		echo '<div style="margin-top:6px">'.$svg.'</div>';
		echo '<div class="crit-sub">Тренд розміру останніх архівів</div>';
	}
	echo '</div>';

	// План/політика
	echo '<div class="crit-card">';
	echo '<h3>Політика зберігання</h3>';
	echo '<div class="crit-kpi">'.esc_html($days_opt).' днів</div>';
	echo '<div class="crit-sub">Макс. архівів: '.$keep_opt.' • Ліміт файлу: '.$size_opt.' МБ</div>';
	if ($next_cron) {
		echo '<div class="crit-sub" style="margin-top:6px">Наступний WP-Cron: '.esc_html(date_i18n('Y-m-d H:i:s', $next_crон)).'</div>';
	}
	echo '</div>';

	echo '</div>'; // .crit-grid

	// ===== Список архівів (з діями) =====
	if ($archives) {
		echo '<div class="crit-card" style="margin-top:8px">';
		echo '<h3>Останні архіви</h3>';
		echo '<table class="widefat striped crit-table"><thead><tr>
				<th>Файл</th><th style="width:160px">Дата</th><th style="width:120px;text-align:right">Розмір</th><th style="width:220px">Дії</th>
			  </tr></thead><tbody>';
		foreach (array_slice($archives, 0, 10) as $f) {
			$bn  = basename($f);
			$t   = @filemtime($f);
			$sz  = @filesize($f);

			$restore_url = wp_nonce_url(
				add_query_arg(['page'=>'critical-log-rotation','crit_restore_backup'=>1,'file'=>$bn], admin_url('admin.php')),
				'crit_backup_action',
				'crit_backup_nonce'
			);
			$delete_url = wp_nonce_url(
				add_query_arg(['page'=>'critical-log-rotation','crit_del_backup'=>1,'file'=>$bn], admin_url('admin.php')),
				'crit_backup_action',
				'crit_backup_nonce'
			);

			echo '<tr>
					<td class="crit-mono">'.esc_html($bn).'</td>
					<td>'.esc_html($t ? date_i18n('Y-m-d H:i:s', $t) : '—').'</td>
					<td style="text-align:right">'.esc_html(crit_human_bytes($sz)).'</td>
					<td class="crit-actions">
						<a href="'.esc_url($restore_url).'" class="button button-small" onclick="return confirm(\'Відновити журнал з цього архіву?\')">♻️ Відновити</a>
						<a href="'.esc_url($delete_url).'"  class="button button-small" onclick="return confirm(\'Видалити архів?\')">🗑️ Видалити</a>
					</td>
				  </tr>';
		}
		echo '</tbody></table>';
		echo '<p class="description">Показано останні 10 архівів. Старіші — видаляються політикою зберігання.</p>';
		echo '</div>';
	}

	// ===== Форма налаштувань =====
	$size  = get_option('crit_log_max_size', 5);
	$files = get_option('crit_log_keep_files', 7);
	$days  = get_option('crit_log_max_days', 30);

	echo '<form method="post" style="margin-top:14px">';
	wp_nonce_field('crit_log_rotation_save', 'crit_log_rotation_nonce');
	echo '<p><label>📦 Максимальний розмір лог-файлу (МБ):
			<input type="number" name="crit_log_max_size" value="' . esc_attr($size) . '" min="1" max="100" style="width:90px">
		  </label></p>';
	echo '<p><label>🧾 Зберігати останніх файлів:
			<input type="number" name="crit_log_keep_files" value="' . esc_attr($files) . '" min="1" max="30" style="width:90px">
		  </label></p>';
	echo '<p><label>🕐 Видаляти записи старше (днів):
			<input type="number" name="crit_log_max_days" value="' . esc_attr($days) . '" min="1" max="365" style="width:90px">
		  </label></p>';
	echo '<p><input type="submit" name="crit_save_rotation" class="button-primary" value="💾 Зберегти"></p>';
	echo '</form>';

	// Кнопка ручного запуску з nonce
	echo '</p>';
	$run_url = wp_nonce_url(
		add_query_arg(['page'=>'critical-log-rotation','crit_run_rotation'=>1], admin_url('admin.php')),
		'crit_run_rotation_now',
		'crit_rotation_now_nonce'
	);
	echo '<a href="'.esc_url($run_url).'" class="button">🔁 Виконати зараз</a><hr><p style="color:#777;">Ротація виконується автоматично раз на добу через WP-Cron. ';

	echo '</div>'; // .wrap
}
