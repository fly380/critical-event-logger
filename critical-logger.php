<?php
/**
 * Plugin Name: Critical Event Logger
 * Plugin URI: https://github.com/fly380/critical-event-logger
 * Description: Логування критичних подій із швидким AJAX-переглядом, парсером «склеєних» рядків, частотністю IP, Geo/пул-визначенням, ручним блокуванням (.htaccess для Apache 2.2/2.4), ротацією й очищенням логів, GeoBlock та опційними AI-інсайтами.
 * Version: 2.6.5
 * Author: Казмірчук Андрій
 * Author URI: https://www.facebook.com/fly380/
 * Text Domain: fly380
 * Requires PHP: 7.2
 * Requires at least: 5.8
 * Tested up to: 6.6 - 6.8
 * License: GPLv2 or later
 * Plugin URI: https://github.com/fly380/critical-event-logger
 * Update URI: https://github.com/fly380/critical-event-logger
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Domain Path: /languages
 * Copyright © 2025 Казмірчук Андрій
 */

if ( is_admin() ) {
	// 1) Підключаємо PUC — або через Composer, або через локальну папку plugin-update-checker/.
	if ( file_exists( __DIR__ . '/vendor/autoload.php' ) ) {
		require_once __DIR__ . '/vendor/autoload.php';
	} elseif ( file_exists( __DIR__ . '/plugin-update-checker/plugin-update-checker.php' ) ) {
		require_once __DIR__ . '/plugin-update-checker/plugin-update-checker.php';
	}

	// 2) Ініціалізуємо апдейтер (публічний репозиторій).
	if ( class_exists( \YahnisElsts\PluginUpdateChecker\v5\PucFactory::class ) ) {
		$updateChecker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
			'https://github.com/fly380/critical-event-logger', // URL репозиторію
			__FILE__,										   // головний файл плагіна
			'critical-event-logger'							 // slug = назва папки плагіна
		);

		// Брати ZIP з релізів:
		$updateChecker->getVcsApi()->enableReleaseAssets();

		// Явно вкажемо гілку джерела (за потреби):
		$updateChecker->setBranch('main');
	}
}

ob_start();
defined('ABSPATH') || exit;

/* Підключаємо основні файли плагіна */
require_once plugin_dir_path(__FILE__) . 'logger.php';
require_once plugin_dir_path(__FILE__) . 'logger-hooks.php';

/**
 * Розрізає сирий текст лога на окремі записи навіть якщо між ними немає \n
 * Кожен запис починається з мітки часу: [YYYY-MM-DD HH:MM:SS]
 */
function crit_split_log_entries(string $raw): array {
	$raw = trim($raw);
	if ($raw === '') return [];
	$parts = preg_split('/(?=\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\])/', $raw);
	return array_values(array_filter(array_map('trim', $parts), static function($s){ return $s !== ''; }));
}

/**
 * Tail по ЗАПИСАХ: читає до 1 МБ з хвоста файлу, потім ріже регуляркою
 */
function crit_tail_entries(string $file, int $limit = 300): array {
	if (!file_exists($file) || $limit <= 0) return [];
	$fp = @fopen($file, 'rb');
	if (!$fp) return [];

	$filesize = @filesize($file);
	if ($filesize === false || $filesize <= 0) { // ← файл порожній
		fclose($fp);
		return [];
	}

	$read = min($filesize, 1024 * 1024); // до 1 МБ
	// fseek на 0 з кінця еквівалентно позиції в кінці — але тут read > 0 гарантовано
	if ($read > 0) {
		fseek($fp, -$read, SEEK_END);
		$chunk = fread($fp, $read) ?: '';
	} else {
		$chunk = '';
	}
	fclose($fp);

	if ($chunk === '') return [];
	$entries = crit_split_log_entries($chunk);
	return array_slice($entries, -$limit);
}

/**
 * Акуратно дописує рядок у лог: гарантує перенос перед новим записом і додає \n в кінці
 * $line очікується БЕЗ \n в кінці.
 */
function crit_append_log_line(string $file, string $line): void {
	$line = rtrim($line, "\r\n");
	$need_nl = false;
	if (file_exists($file) && filesize($file) > 0) {
		$fp = @fopen($file, 'rb');
		if ($fp) {
			fseek($fp, -1, SEEK_END);
			$last = fgetc($fp);
			fclose($fp);
			if ($last !== "\n") $need_nl = true;
		}
	}
	$prefix = $need_nl ? "\n" : '';
	@file_put_contents($file, $prefix . $line . "\n", FILE_APPEND | LOCK_EX);
}

/**
 * Швидко читає останні N рядків великого файла (tail).
 * Безпечна щодо порожнього файлу.
 */
function crit_tail_lines($file, $lines = 300) {
	if (!file_exists($file) || $lines <= 0) return [];

	$fp = @fopen($file, 'rb');
	if (!$fp) return [];

	fseek($fp, 0, SEEK_END);
	$filesize = ftell($fp);

	if ($filesize <= 0) { // ← файл порожній
		fclose($fp);
		return [];
	}

	$pos = -1;
	$line_count = 0;
	$buffer = '';
	$chunks = [];

	while ($line_count < $lines && -$pos < $filesize) {
		fseek($fp, $pos, SEEK_END);
		$char = fgetc($fp);
		if ($char === "\n" && $buffer !== '') {
			$chunks[] = strrev($buffer);
			$buffer = '';
			$line_count++;
		} elseif ($char !== false) {
			$buffer .= $char;
		}
		$pos--;
	}

	if ($buffer !== '') $chunks[] = strrev($buffer);
	fclose($fp);

	$chunks = array_reverse($chunks);
	return array_values($chunks);
}

/* Обробники помилок */
set_error_handler('critical_logger_error_handler');
register_shutdown_function('critical_logger_shutdown_handler');

/* Адмін-меню */
add_action('admin_menu', function() {
	add_menu_page(
		'Логи подій',
		'Переглянути логи',
		'manage_options',
		'critical-event-logs',
		'critical_logger_admin_page',
		'dashicons-list-view',
		25
	);
});
/* === AJAX: Виявлені IP (за частотою) === */
add_action('wp_ajax_critical_logger_detected_ips', 'critical_logger_detected_ips_cb');
function critical_logger_detected_ips_cb() {
	if (! current_user_can('manage_options')) wp_send_json_error('Недостатньо прав', 403);
	check_ajax_referer('critical_logger_simple_nonce', 'nonce');

	$log_file = plugin_dir_path(__FILE__) . 'logs/events.log';
	if (! file_exists($log_file)) wp_send_json_error('Лог-файл не знайдено', 404);

	$raw = @file_get_contents($log_file) ?: '';
	$all_lines = crit_split_log_entries($raw);
	$ip_counts = [];
	foreach ($all_lines as $ln) {
		if (preg_match('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $ln, $m)) {
			$ip_counts[$m[0]] = ($ip_counts[$m[0]] ?? 0) + 1;
		}
	}
	arsort($ip_counts);

	ob_start();
	if ($ip_counts) {
		// ПОВЕРТАЄМО ЛИШЕ ТАБЛИЦЮ — без додаткового <div>
		echo '<table class="widefat striped" style="width:100%;">';
		echo '<thead><tr>
				<th>IP</th>
				<th>Кількість</th>
				<th>Пул</th>
				<th>Гео</th>
				<th>Дія</th>
			</tr></thead><tbody>';

		foreach ($ip_counts as $fip => $cnt) {
			$color = ($cnt > 10) ? 'color:#c00;font-weight:bold;' : '';

			echo '<tr>';
			echo '<td style="' . esc_attr($color) . '">' . esc_html($fip) . '</td>';
			echo '<td>' . intval($cnt) . '</td>';
			echo '<td class="crit-pool" data-ip="' . esc_attr($fip) . '"><em style="color:#888">…</em></td>';
			echo '<td class="crit-geo"data-ip="' . esc_attr($fip) . '"><em style="color:#888">…</em></td>';
			echo '<td>';

			// Кнопка "Блокувати" — одиночний IP
			echo '<form method="post" style="display:inline; margin-right:4px;">' .
				 wp_nonce_field('manual_block_ip_action', 'manual_block_ip_nonce', true, false) .
				 '<input type="hidden" name="manual_ip_address" value="' . esc_attr($fip) . '">' .
				 '<input type="submit" name="manual_block_ip" class="button button-small" value="Блокувати">' .
			'</form>';

			// Кнопка "Блокувати пул" — hidden порожній, кнопка вимкнена (JS підставить пул і увімкне)
			echo '<form method="post" class="js-block-pool-form" data-ip="' . esc_attr($fip) . '" style="display:inline;">' .
				 wp_nonce_field('manual_block_ip_action', 'manual_block_ip_nonce', true, false) .
				 '<input type="hidden" name="manual_ip_address" class="js-pool-input" value="">' .
				 '<input type="submit" name="manual_block_ip" class="button button-small button-secondary js-block-pool" value="Блокувати пул" disabled title="Очікуємо визначення пулу…">' .
			'</form>';

			echo '</td></tr>';
		}

		echo '</tbody></table>';
	} else {
		echo '<div style="padding:12px; color:#666;">IP-адреси не знайдено.</div>';
	}

	$html = ob_get_clean();
	wp_send_json_success(['html' => $html]);
}



/* === AJAX: головна таблиця лога (частина сторінки) === */
add_action('wp_ajax_critical_logger_log_table', 'critical_logger_log_table_cb');
function critical_logger_log_table_cb() {
	if ( ! current_user_can('manage_options') ) wp_send_json_error('Недостатньо прав', 403);
	check_ajax_referer('critical_logger_simple_nonce', 'nonce');

	$log_file = plugin_dir_path(__FILE__) . 'logs/events.log';
	if ( ! file_exists($log_file) ) wp_send_json_error('Лог-файл не знайдено', 404);

	// скільки рядків показувати (можеш підкрутити через $_POST['limit'])
	$limit = isset($_POST['limit']) ? max(50, min(2000, intval($_POST['limit']))) : 500;

	$lines = crit_tail_entries($log_file, $limit);
	// підрахунок частоти IP (для підсвічування)
	$ip_counts = array();
	foreach ($lines as $ln) {
		if (preg_match('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $ln, $m)) {
			$ip_counts[$m[0]] = ($ip_counts[$m[0]] ?? 0) + 1;
		}
	}

	ob_start();
	echo '<table class="widefat fixed striped" style="width:100%;">';
	echo '<thead><tr><th>Час</th><th>IP</th><th>Користувач</th><th>Рівень</th><th>Повідомлення</th><th>Дія</th></tr></thead><tbody>';

	// показуємо від нових до старих
	foreach (array_reverse($lines) as $line) {
		$time = $ip = $username = $level = $message = '';
		if (preg_match('/^\[([0-9\- :]+)\]\[([^\]]+)\]\[([^\]]*)\]\[([^\]]+)\]\s?(.*)$/', $line, $m)) {
			[$time, $ip, $username, $level, $message] = array_slice($m, 1);
		} elseif (preg_match('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $line, $mm)) {
			$ip = $mm[0]; $message = $line;
		} else {
			$message = $line;
		}

		$style = (! empty($ip) && ($ip_counts[$ip] ?? 0) > 10) ? 'color:#c00;font-weight:bold;' : '';

		echo '<tr>';
		echo '<td style="font-family:monospace;">' . esc_html($time) . '</td>';
		echo '<td style="' . esc_attr($style) . '">' . esc_html($ip) . '</td>';
		echo '<td>' . esc_html($username) . '</td>';
		echo '<td>' . esc_html($level) . '</td>';
		echo '<td style="font-family:monospace; white-space:pre-wrap;">' . esc_html($message) . '</td>';
		echo '<td>';

		if ($ip) {
			// форма блокування прямо з AJAX-відповіді
			echo '<form method="post" style="display:inline;">' .
				 wp_nonce_field('manual_block_ip_action', 'manual_block_ip_nonce', true, false) .
				 '<input type="hidden" name="manual_ip_address" value="' . esc_attr($ip) . '">' .
				 '<input type="submit" name="manual_block_ip" class="button button-small" value="Блокувати">' .
				 '</form>';
		} else {
			echo '—';
		}

		echo '</td></tr>';
	}
	echo '</tbody></table>';

	$html = ob_get_clean();
	wp_send_json_success(['html' => $html]);
}


/* AJAX: оновити textarea з логами (старий handler — зберіг) */
add_action('wp_ajax_critical_logger_reload_logs', 'critical_logger_reload_logs_callback');

function critical_logger_reload_logs_callback() {
	if (! current_user_can('manage_options')) {
		wp_send_json_error('Недостатньо прав', 403);
	}

	check_ajax_referer('critical_logger_simple_nonce', 'nonce');

	$log_file = plugin_dir_path(__FILE__) . 'logs/events.log';
	if (! file_exists($log_file)) {
		wp_send_json_error('Лог-файл не знайдено', 404);
	}

	$raw = @file_get_contents($log_file) ?: '';
	$lines = crit_split_log_entries($raw);
	wp_send_json_success(array_values($lines));
}

/* === AJAX: батч-гео та пул для списку IP === */
add_action('wp_ajax_critical_logger_geo_batch', 'critical_logger_geo_batch_cb');
function critical_logger_geo_batch_cb() {
	if (! current_user_can('manage_options')) wp_send_json_error('Недостатньо прав', 403);
	check_ajax_referer('critical_logger_simple_nonce', 'nonce');

	$ips = isset($_POST['ips']) ? (array) $_POST['ips'] : [];
	$out = [];

	foreach ($ips as $ip) {
		$ip = sanitize_text_field($ip);
		if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;

		// пул (вже кешується всередині функцій)
		$pool_raw = function_exists('crit_get_ip_pool') ? crit_get_ip_pool($ip) : ['-'];
		if (!is_array($pool_raw)) $pool_raw = [$pool_raw];
		$pool = implode(', ', array_filter($pool_raw));

		// гео (кеш транзієнтом)
		$geo_country = ''; $geo_city = '';
		$cache_key = 'crit_geo_' . md5($ip);
		$cached_geo = get_transient($cache_key);
		if ($cached_geo !== false) {
			$geo_country = $cached_geo['country'] ?? '';
			$geo_city	= $cached_geo['city'] ?? '';
		} else {
			$resp = wp_remote_get("http://ip-api.com/json/{$ip}?fields=status,country,city", ['timeout' => 3]);
			if (!is_wp_error($resp)) {
				$data = json_decode(wp_remote_retrieve_body($resp), true);
				if (!empty($data['status']) && $data['status'] === 'success') {
					$geo_country = $data['country'] ?? '';
					$geo_city	= $data['city'] ?? '';
					set_transient($cache_key, ['country' => $geo_country, 'city' => $geo_city], 12 * HOUR_IN_SECONDS);
				}
			}
		}
		$geo = trim(($geo_country ?: '') . ($geo_city ? ', ' . $geo_city : ''));

		$out[$ip] = [
			'pool' => $pool ?: '-',
			'geo'=> $geo ?: '—',
		];
	}

	wp_send_json_success($out);
}

/* Підключення стилів/скриптів для адмін-сторінки */
add_action('admin_enqueue_scripts', function($hook) {
	if ($hook !== 'toplevel_page_critical-event-logs') return;
	wp_enqueue_style('crit-logger-admin-css', plugin_dir_url(__FILE__) . 'css/critical-logger-admin.css', array(), '1.0');
	wp_enqueue_script('critical-logger-simple-js', plugin_dir_url(__FILE__) . 'js/critical-logger-simple.js', array('jquery'), '1.1', true);
	wp_localize_script('critical-logger-simple-js', 'criticalLoggerSimpleData', array(
		'ajaxUrl' => admin_url('admin-ajax.php'),
		'nonce' => wp_create_nonce('critical_logger_simple_nonce'),
	));
});

/**
 * ======= Точне визначення пулу через RDAP (офіційні реєстри) =======
 * 1) Пробуємо ARIN RDAP і дозволяємо редірект до потрібного RIR
 * 2) Якщо ні — пробуємо напряму RIPE RDAP
 * 3) Повертаємо строго startAddress-endAddress
 */
function crit_get_ip_pool_via_rdap($ip) {
	$cache_key = 'crit_pool_rdap_' . md5($ip);
	$cached = get_transient($cache_key);
	if ($cached !== false) return $cached;

	$endpoints = array(
		// ARIN зробить редірект у потрібний RIR
		"https://rdap.arin.net/registry/ip/" . rawurlencode($ip),
		// запасний прямий RIPE
		"https://rdap.db.ripe.net/ip/" . rawurlencode($ip),
	);

	foreach ($endpoints as $url) {
		$resp = wp_remote_get($url, array(
			'timeout'	=> 12,
			'redirection'=> 5,
			'headers'	=> array('Accept' => 'application/rdap+json, application/json'),
		));
		if (is_wp_error($resp)) continue;

		$code = wp_remote_retrieve_response_code($resp);
		if ($code < 200 || $code >= 300) continue;

		$body = wp_remote_retrieve_body($resp);
		if (! $body) continue;

		$data = json_decode($body, true);
		if (! is_array($data)) continue;

		// RDAP може повертати поля на верхньому рівні або всередині "network"
		$start = $data['startAddress'] ?? ($data['network']['startAddress'] ?? null);
		$end = $data['endAddress'] ?? ($data['network']['endAddress'] ?? null);

		if ($start && $end && filter_var($start, FILTER_VALIDATE_IP) && filter_var($end, FILTER_VALIDATE_IP)) {
			$range = $start . '-' . $end;
			set_transient($cache_key, $range, 7 * DAY_IN_SECONDS);
			return $range;
		}
	}

	return ''; // нехай вирішує наступний шар
}

/**
 * Запасний метод через WHOIS (сокет, без shell_exec), реєстр RIPE
 */
function crit_get_ip_pool_via_whois_socket($ip) {
	$cache_key = 'crit_pool_ripewhois_' . md5($ip);
	$cached = get_transient($cache_key);
	if ($cached !== false) return $cached;

	$fp = @fsockopen("whois.ripe.net", 43, $errno, $errstr, 10);
	if (!$fp) return '';
	fwrite($fp, $ip . "\r\n");
	$response = '';
	while (!feof($fp)) $response .= fgets($fp, 256);
	fclose($fp);

	if (preg_match('/inetnum:\s*([0-9\.]+)\s*-\s*([0-9\.]+)/i', $response, $m)) {
		$range = trim($m[1]) . '-' . trim($m[2]);
		set_transient($cache_key, $range, 7 * DAY_IN_SECONDS);
		return $range;
	}
	return '';
}

/**
 * REST RIPE (fallback). ВАЖЛИВО: виправлено regex (не використовуємо кириличне \д)
 */
function crit_get_ip_pool_via_ripe_precise($ip) {
	$cache_key = 'crit_pool_ripe_precise_' . md5($ip);
	$cached = get_transient($cache_key);
	if ($cached !== false) return $cached;

	$url = 'https://rest.db.ripe.net/search.json?query-string=' . urlencode($ip) . '&type-filter=inetnum';
	$resp = wp_remote_get($url, ['timeout' => 10]);
	if (is_wp_error($resp)) return '';

	$body = wp_remote_retrieve_body($resp);
	$data = json_decode($body, true);
	if (empty($data['objects']['object'])) return '';

	$target = sprintf('%u', ip2long($ip));
	$best_start = $best_end = null;
	$best_span = PHP_INT_MAX;

	foreach ($data['objects']['object'] as $obj) {
		foreach ($obj['attributes']['attribute'] ?? [] as $attr) {
			if (strtolower($attr['name'] ?? '') !== 'inetnum') continue;
			if (!preg_match('/^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$/', trim($attr['value']), $m)) continue;

			$start = sprintf('%u', ip2long($m[1]));
			$end = sprintf('%u', ip2long($m[2]));
			if ($start <= $target && $target <= $end) {
				$span = $end - $start;
				if ($span < $best_span) {
					$best_start = $start;
					$best_end = $end;
					$best_span = $span;
				}
			}
		}
	}

	if ($best_start && $best_end) {
		$range = long2ip($best_start) . '-' . long2ip($best_end);
		set_transient($cache_key, $range, 7 * DAY_IN_SECONDS);
		return $range;
	}

	return '';
}

/**
 * Перетворює IP-діапазон start..end у масив CIDR рядків.
 * Алгоритм: розбиває діапазон на мінімальний набір CIDR-блоків.
 */
function crit_ip_range_to_cidrs($start_ip, $end_ip) {
	$start = ip2long($start_ip);
	$end = ip2long($end_ip);
	if ($start === false || $end === false || $start > $end) return [];

	$cidrs = [];

	while ($start <= $end) {
		// визначаємо найбільший блок
		$maxSize = 32;
		while ($maxSize > 0) {
			$mask = pow(2, 32 - $maxSize);
			if (($start & ($mask - 1)) === 0) break;
			$maxSize--;
		}

		// не перевищуємо залишок
		$remaining = $end - $start + 1;
		while (pow(2, 32 - $maxSize) > $remaining) {
			$maxSize++;
		}

		$cidrs[] = long2ip($start) . '/' . $maxSize;
		$start += pow(2, 32 - $maxSize);
	}

	return $cidrs;
}

/**
 * Безпечне конвертування діапазону у CIDR (працює на PHP 7.2–8.3)
 */
if (! function_exists('crit_ip_range_to_cidrs_safe')) {
	function crit_ip_range_to_cidrs_safe($start_ip, $end_ip) {
		if (! filter_var($start_ip, FILTER_VALIDATE_IP) || ! filter_var($end_ip, FILTER_VALIDATE_IP)) {
			return [];
		}
		$start = sprintf('%u', ip2long($start_ip));
		$end = sprintf('%u', ip2long($end_ip));
		if ($end < $start) return [];

		$cidrs = [];
		while ($end >= $start) {
			$max_size = 32;
			while ($max_size > 0) {
				$mask = pow(2, 32 - ($max_size - 1));
				if (($start & ($mask - 1)) != 0) break;
				if ($start + $mask - 1 > $end) break;
				$max_size--;
			}
			$cidrs[] = long2ip($start) . '/' . $max_size;
			$start += pow(2, 32 - $max_size);
		}
		return $cidrs;
	}
}

/**
 * GeoIP fallback: повертає країну
 */
function crit_get_ip_pool_via_geoip($ip) {
	if (function_exists('geoip_record_by_name')) {
		$record = @geoip_record_by_name($ip);
		if ($record && !empty($record['country_name'])) return $record['country_name'];
	}
	return '';
}

/**
 * ======= Основна функція: повертає найточніший пул IP =======
 * Порядок: RDAP → WHOIS сокет → REST RIPE → fallback /23
 */
function crit_get_ip_pool($ip) {
	if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['-'];

	// 1) RDAP
	$rdap = crit_get_ip_pool_via_rdap($ip);
	if (!empty($rdap)) return [$rdap];

	// 2) Точний RIPE (новий шар)
	$ripe_precise = crit_get_ip_pool_via_ripe_precise($ip);
	if (!empty($ripe_precise)) return [$ripe_precise];

	// 3) WHOIS сокет
	$whois = crit_get_ip_pool_via_whois_socket($ip);
	if (!empty($whois)) return [$whois];

	// 4) REST RIPE (fallback) — лише якщо справді існує у твоєму проекті
	if (function_exists('crit_get_ip_pool_via_ripe')) {
		$ripe = crit_get_ip_pool_via_ripe($ip);
		if (!empty($ripe)) return [$ripe];
	}

	// 5) Обережний fallback /23 — тільки коли нічого не вдалось отримати
	$prefix = 23;
	$mask = 0xFFFFFFFF << (32 - $prefix);
	$net= sprintf('%u', ip2long($ip)) & $mask;
	$range = long2ip($net) . '-' . long2ip($net + pow(2, 32 - $prefix) - 1);
	return [$range];
}

/**
 * Розгортання у список IP (CIDR або start-end або одиночний IP)
 */
function crit_expand_cidr_to_ips($cidr_list) {
	$all_ips = [];
	foreach ($cidr_list as $cidr) {
		if (strpos($cidr, '-') !== false) {
			// Якщо діапазон start-end
			list($start_ip, $end_ip) = explode('-', $cidr);
			$all_ips = array_merge($all_ips, crit_ip_range_to_ips(trim($start_ip), trim($end_ip)));
		} elseif (strpos($cidr, '/') !== false) {
			// Якщо CIDR
			$all_ips = array_merge($all_ips, crit_cidr_to_ips($cidr));
		} else {
			$all_ips[] = $cidr;
		}
	}
	return $all_ips;
}

/**
 * Перетворення CIDR у всі IP (обережно з великими мережами)
 */
if (!function_exists('crit_cidr_to_ips')) {
	function crit_cidr_to_ips($cidr) {
		if (!preg_match('/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/', trim($cidr), $m)) return [];
		$ip = $m[1];
		$prefix = (int)$m[2];
		if ($prefix < 0 || $prefix > 32) return [];

		$ip_long = ip2long($ip);
		if ($ip_long === false) return [];

		$mask = $prefix == 0 ? 0 : (~0 << (32 - $prefix)) & 0xFFFFFFFF;
		$network = $ip_long & $mask;
		$broadcast = $network | (~$mask & 0xFFFFFFFF);

		$size = ($broadcast - $network + 1);
		// захист від надвеликих списків
		if ($size > 65536) return [$ip . '/' . $prefix];

		$ips = [];
		for ($i = $network; $i <= $broadcast; $i++) {
			$ips[] = long2ip($i);
		}
		return $ips;
	}
}

// Перетворення діапазону start-end у всі IP
function crit_ip_range_to_ips($start_ip, $end_ip) {
	$start = ip2long($start_ip);
	$end = ip2long($end_ip);
	if ($start === false || $end === false || $start > $end) return [];
	$ips = [];
	for ($i = $start; $i <= $end; $i++) {
		$ips[] = long2ip($i);
	}
	return $ips;
}

/**
 * WHOIS fallback через ARIN для IP, які не знайшлися в RIPE (shell_exec)
 * (Залишено як крайній варіант для сумісності; у більшості випадків RDAP вирішить точніше)
 */
function crit_get_ip_pool_via_whois($ip) {
	$cache_key = 'crit_pool_whois_' . md5($ip);
	$cached = get_transient($cache_key);
	if ($cached !== false) return $cached;

	$cmd = "whois " . escapeshellarg($ip);
	$output = @shell_exec($cmd);
	if (!$output) return '';

	// шукаємо inetnum або NetRange
	if (preg_match('/(?:inetnum|NetRange):\s*([0-9\.]+)\s*-\s*([0-9\.]+)/i', $output, $m)) {
		$cidrs = crit_ip_range_to_cidrs($m[1], $m[2]);
		$res = implode(' ', $cidrs);
		if ($res) set_transient($cache_key, $res, 7 * DAY_IN_SECONDS);
		return $res;
	}

	return '';
}

/* Видалення старих записів у логах */
function critical_logger_cleanup_old_logs($days = 30) {
	$log_file = plugin_dir_path(__FILE__) . 'logs/events.log';
	if (! file_exists($log_file)) return;

	$raw = @file_get_contents($log_file) ?: '';
	$entries = crit_split_log_entries($raw);
	if (!$entries) return;

	$now = time();
	$limit_ts = $now - ($days * DAY_IN_SECONDS);
	$kept = [];

	foreach ($entries as $ln) {
		if (preg_match('/^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]/', $ln, $m)) {
			$ts = strtotime($m[1]);
			if ($ts !== false && $ts >= $limit_ts) {
				$kept[] = $ln;
			}
		} else {
			// якщо не змогли розпізнати — не видаляємо
			$kept[] = $ln;
		}
	}

	// Записуємо назад з одним \n між записами і \n в кінці файлу
	$out = implode("\n", $kept);
	if ($out !== '') $out .= "\n";
	@file_put_contents($log_file, $out, LOCK_EX);
}


/* Виконуємо очищення/експорт/очистку тільки при вході в сторінку */
add_action('admin_init', function() {
	if (isset($_GET['page']) && $_GET['page'] === 'critical-event-logs') {
		critical_logger_cleanup_old_logs(30);

		// Очистити лог
		if (isset($_POST['clear_log']) && current_user_can('manage_options') && check_admin_referer('clear_log_action', 'clear_log_nonce')) {
			$log_file = plugin_dir_path(__FILE__) . 'logs/events.log';
			file_put_contents($log_file, '', LOCK_EX);
			wp_safe_redirect(add_query_arg('cleared', '1', menu_page_url('critical-event-logs', false)));
			exit;
		}

		// Експорт у CSV
		if (isset($_POST['export_csv']) && current_user_can('manage_options') && check_admin_referer('export_csv_action', 'export_csv_nonce')) {
			$log_file = plugin_dir_path(__FILE__) . 'logs/events.log';
			if (! file_exists($log_file)) wp_die('Лог-файл не знайдено для експорту.');

			// Вивантаження CSV
			if (! ob_get_level()) ob_start();
			ob_end_clean();
			header('Content-Type: text/csv; charset=utf-8');
			header('Content-Disposition: attachment; filename=critical-logs-' . date('Y-m-d') . '.csv');
			$output = fopen('php://output', 'w');
			fputcsv($output, array('Event log'));
			$raw = @file_get_contents($log_file) ?: '';
			$lines = crit_split_log_entries($raw);
			foreach ($lines as $line) fputcsv($output, array($line));
			fclose($output);
			exit;
		}
	}
});

/* Головна адмін-сторінка для перегляду логів */
function critical_logger_admin_page() {
	ob_start();

	$log_file = plugin_dir_path(__FILE__) . 'logs/events.log';

	// --- Обробка: Очистити лог ---
	if (isset($_POST['clear_logs']) && current_user_can('manage_options')) {
		check_admin_referer('critical_logger_clear_logs_action', 'critical_logger_clear_logs_nonce');
		if (file_exists($log_file)) {
			file_put_contents($log_file, '');
		}
		echo '<div class="notice notice-success"><p>Лог очищено.</p></div>';
	}

	// --- Ручне блокування IP, CIDR або діапазону (безпечна версія) ---
	if (isset($_POST['manual_block_ip']) && ! empty($_POST['manual_ip_address']) && current_user_can('manage_options')) {
		try {
			if (! empty($_POST['manual_block_ip_nonce'])) {
				check_admin_referer('manual_block_ip_action', 'manual_block_ip_nonce');
			}

			$input = trim(sanitize_text_field($_POST['manual_ip_address']));
			$blocked_entries = [];

			// CIDR (напр. 178.128.16.0/20)
			if (preg_match('/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/', $input)) {
				$blocked_entries[] = $input;

			// Діапазон (напр. 178.128.16.0 - 178.128.31.255)
			} elseif (preg_match('/^(\d{1,3}\.){3}\d{1,3}\s*-\s*(\d{1,3}\.){3}\d{1,3}$/', $input)) {
				list($start_ip, $end_ip) = preg_split('/\s*-\s*/', $input);
				$cidrs = crit_ip_range_to_cidrs_safe($start_ip, $end_ip);
				if (! empty($cidrs)) {
					$blocked_entries = $cidrs;
					echo '<div class="notice notice-info"><p>Діапазон ' . esc_html($input) . ' перетворено у: ' . esc_html(implode(', ', $cidrs)) . '</p></div>';
				} else {
					echo '<div class="notice notice-error"><p>Не вдалося конвертувати діапазон у CIDR.</p></div>';
				}

			// Один IP
			} elseif (filter_var($input, FILTER_VALIDATE_IP)) {
				$blocked_entries[] = $input;
			} else {
				echo '<div class="notice notice-error"><p>Невірний формат IP, CIDR або діапазону.</p></div>';
			}

			if (! empty($blocked_entries)) {
				$htaccess_path = ABSPATH . '.htaccess';
				$added = false;

				if (file_exists($htaccess_path) && is_writable($htaccess_path)) {
					$ht_contents = file_get_contents($htaccess_path);
					$apache_version = (isset($_SERVER['SERVER_SOFTWARE']) && stripos($_SERVER['SERVER_SOFTWARE'], 'Apache/2.2') !== false) ? 22 : 24;

					foreach ($blocked_entries as $entry_ip) {
						if (strpos($ht_contents, $entry_ip) !== false) continue;

						$eol = (strpos($ht_contents, "\r\n") !== false) ? "\r\n" : "\n";

							if ($apache_version == 22) {
							// === Apache 2.2 (старий синтаксис) ===
							$order_block = "Order allow,deny";
 							 $allow_block = "Allow from all";

 							 $has_order = stripos($ht_contents, $order_block) !== false;
							$has_allow = stripos($ht_contents, $allow_block) !== false;

 							 // --- 1) Якщо немає обох або хоча б однієї директиви — додаємо новий блок АКУРАТНО ---
							if (!$has_order || !$has_allow) {
 								$lines = array(
									'# Blocked by CriticalLogger (Apache 2.2 mode)',
	 								 'Order allow,deny',
	 								 'Allow from all',
							);
								 foreach ($blocked_entries as $bip) {
									$lines[] = "Deny from {$bip}";
							}
 								$new_section = $eol . implode($eol, $lines) . $eol;

 								if (strpos($ht_contents, '# END WordPress') !== false) {
								 $ht_contents = str_replace('# END WordPress', '# END WordPress' . $eol . $new_section, $ht_contents);
								 } else {
									if (substr($ht_contents, -strlen($eol)) !== $eol) {
									$ht_contents .= $eol;
									}
									$ht_contents .= $new_section;
								 }
							 $added = true;

 							 // --- 2) Якщо секція вже є — вставляємо РІВНО після "Allow from all" + EOL ---
							} else {
								 foreach ($blocked_entries as $bip) {
	 								 if (strpos($ht_contents, "Deny from {$bip}") !== false) {
	 								 continue;
									}
									// Матчимо "Allow from all" до кінця рядка, не поглинаючи зайві переноси
									$pattern = '/^(\s*Allow from all)[ \t]*\r?\n/mi';
									$replacement = '$1' . $eol . "Deny from {$bip}" . $eol;

									$new_contents = preg_replace($pattern, $replacement, $ht_contents, 1, $count);
									if ($count > 0) {
									$ht_contents = $new_contents;
									$added = true;
	 								 } else {
	 								 // fallback — додамо в кінець файлу, акуратно
	 								 if (substr($ht_contents, -strlen($eol)) !== $eol) {
										 $ht_contents .= $eol;
	 								 }
	 								 $ht_contents .= "Deny from {$bip}" . $eol;
									$added = true;
	 								 }
	 							}
 							 }

							} else {
 							 // === Apache 2.4+ (новий синтаксис RequireAll) ===
 							 $block_start = '<RequireAll>';
 							 $block_end = '</RequireAll>';

 							 if (strpos($ht_contents, $block_start) !== false && strpos($ht_contents, $block_end) !== false) {
 								// Збираємо всі відсутні "Require not ip ..." і вставляємо ОДНИМ шматком перед </RequireAll>
								 $to_add = array();
 								foreach ($blocked_entries as $bip) {
 								if (strpos($ht_contents, "Require not ip {$bip}") === false) {
									$to_add[] = "Require not ip {$bip}";
								 }
 								}
								 if (!empty($to_add)) {
 								$insert = implode($eol, $to_add) . $eol;

 								// знайдемо позицію останнього </RequireAll>
								 $pos = strrpos($ht_contents, $block_end);
 								if ($pos !== false) {
 									 $before = substr($ht_contents, 0, $pos);
									// гарантуємо рівно один EOL перед вставкою
									if (substr($before, -strlen($eol)) !== $eol) {
 										$insert = $eol . $insert;
 									}
 									 $ht_contents = substr($ht_contents, 0, $pos) . $insert . substr($ht_contents, $pos);
 									 $added = true;
 								}
 								}
 							 } else {
								 // Створюємо новий блок без зайвих порожніх рядків
 								$lines = array(
								 '# Blocked by CriticalLogger (Apache 2.4+ mode)',
								 '<RequireAll>',
								 'Require all granted',
								 );
 								foreach ($blocked_entries as $bip) {
 								$lines[] = "Require not ip {$bip}";
 								}
							$lines[] = '</RequireAll>';

 								$new_block = $eol . implode($eol, $lines) . $eol;

							if (strpos($ht_contents, '# END WordPress') !== false) {
 								$ht_contents = str_replace('# END WordPress', '# END WordPress' . $eol . $new_block, $ht_contents);
 								} else {
 								if (substr($ht_contents, -strlen($eol)) !== $eol) {
 									 $ht_contents .= $eol;
								 }
 								$ht_contents .= $new_block;
 								}
 								$added = true;
							}
							}

						$added = true;
					}

					if ($added && @file_put_contents($htaccess_path, $ht_contents, LOCK_EX) !== false) {
						echo '<div class="notice notice-success"><p>Додано у .htaccess: ' . esc_html(implode(', ', $blocked_entries)) . '</p></div>';
					} else {
						echo '<div class="notice notice-warning"><p>Не вдалося записати у .htaccess або записи вже існують.</p></div>';
					}
				} else {
					// Якщо .htaccess недоступний — пишемо у blocked_ips.txt
					$plugin_block_file = plugin_dir_path(__FILE__) . 'blocked_ips.txt';
					$existing = file_exists($plugin_block_file)
						? file($plugin_block_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)
						: [];
					$new_entries = array_diff($blocked_entries, $existing);
					if (! empty($new_entries)) {
						@file_put_contents($plugin_block_file, implode(PHP_EOL, array_merge($existing, $new_entries)) . PHP_EOL, LOCK_EX);
						echo '<div class="notice notice-success"><p>Додано у blocked_ips.txt: ' . esc_html(implode(', ', $new_entries)) . '</p></div>';
					}
				}

				// Логування
				if (file_exists($log_file ?? '') && ! empty($added)) {
					foreach ($blocked_entries as $entry_ip) {
						$entry = '[' . date('Y-m-d H:i:s') . '][System][admin][INFO] Заблоковано вручну: ' . $entry_ip;
						crit_append_log_line($log_file, $entry);

					}
				}
			}

		} catch (Throwable $e) {
			echo '<div class="notice notice-error"><p>Помилка виконання: ' . esc_html($e->getMessage()) . '</p></div>';
		}
	}

	// --- Інтерфейс ---
	echo '<div class="wrap">';
	echo '<h1>Critical Event Logger</h1>';

	if (! file_exists($log_file)) {
		echo '<div class="notice notice-error"><p>Файл логів не знайдено: ' . esc_html($log_file) . '</p></div></div>';
		if (ob_get_level()) ob_end_flush();
		return;
	}

	$raw = @file_get_contents($log_file) ?: '';
	$all_lines = crit_split_log_entries($raw);
	$total_logs = count($all_lines);

	echo '<p>Всього записів: <strong>' . esc_html($total_logs) . '</strong></p>';

	// Кнопки дій
	echo '<div style="margin-bottom:12px;">';
	echo '<button id="crit-reload-logs" type="button" class="button">Оновити</button> ';
	echo '<form method="post" style="display:inline;">' . wp_nonce_field('critical_logger_clear_logs_action', 'critical_logger_clear_logs_nonce', true, false);
	echo '<input type="hidden" name="clear_logs" value="1">';
	echo '<input type="submit" class="button button-secondary" value="Очистити лог" onclick="return confirm(\'Очистити лог? Це незворотно.\');">';
	echo '</form> ';
	echo '</div>';

	// --- Підрахунок частоти IP ---
	$ip_counts = [];
	foreach ($all_lines as $ln) {
		if (preg_match('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $ln, $m)) {
			$ip_counts[$m[0]] = ($ip_counts[$m[0]] ?? 0) + 1;
		}
	}

	// --- Таблиця логів (AJAX) ---
	echo '<div style="max-height:270px; overflow-y:auto; border:1px solid #ddd; border-radius:6px; padding:6px; background:#fff;">';
	echo '<div id="crit-log-container" style="padding:12px; color:#666;">Завантаження лога…</div>';
	echo '</div>';

	echo '<div style="margin-top:16px;">';
	echo '<h3>Виявлені IP (за частотою появи)</h3>';
	echo '<div id="crit-detected-container" style="max-height:250px; overflow-y:auto; border:1px solid #ddd; padding:8px; background:#fff;">';
	echo '<div style="padding:12px; color:#666;">Завантаження…</div>';
	echo '</div>';
	echo '</div>';

	// --- Блок ручного блокування IP ---
	echo '<div style="margin-top:20px; padding:10px; border:1px solid #ccc; background:#fff; border-radius:6px;">';
	echo '<h3>Заблокувати IP вручну</h3>';
	echo '<form method="post" style="margin-top:8px;">';
	wp_nonce_field('manual_block_ip_action', 'manual_block_ip_nonce', true, true);
	echo '<input type="text" name="manual_ip_address" placeholder="Введіть IP-адресу" style="width:200px;"> ';
	echo '<input type="submit" name="manual_block_ip" class="button button-primary" value="Заблокувати">';
	echo '</form>';
	echo '</div>';
	?>
<script>
(function($){

// 1) ЛОГ — повертаємо jqXHR
window.critFetchLogTable = function(limit){
	return $.post(ajaxurl, {
	action: 'critical_logger_log_table',
	nonce: '<?php echo wp_create_nonce("critical_logger_simple_nonce"); ?>',
	limit: limit || 500
	}).done(function(resp){
	if (resp && resp.success && resp.data && resp.data.html){
		$('#crit-log-container').html(resp.data.html);
	} else {
		$('#crit-log-container').html('<div style="padding:12px; color:#c00;">Не вдалося завантажити лог.</div>');
	}
	}).fail(function(){
	$('#crit-log-container').html('<div style="padding:12px; color:#c00;">Помилка AJAX-запиту при завантаженні лога.</div>');
	});
};

// 3) ВИЯВЛЕНІ IP — ПОВНА ТАБЛИЦЯ (нова)
window.critFetchDetectedIPs = function(){
	return $.post(ajaxurl, {
	action: 'critical_logger_detected_ips',
	nonce: '<?php echo wp_create_nonce("critical_logger_simple_nonce"); ?>'
	}).done(function(resp){
	if (resp && resp.success && resp.data && resp.data.html){
		$('#crit-detected-container').html(resp.data.html);
		// після вставки нової таблиці — підвантажити гео/пул для її рядків
		window.critFetchGeoBatch();
	} else {
		$('#crit-detected-container').html('<div style="padding:12px; color:#c00;">Не вдалося завантажити список IP.</div>');
	}
	}).fail(function(){
	$('#crit-detected-container').html('<div style="padding:12px; color:#c00;">Помилка AJAX-запиту при завантаженні списку IP.</div>');
	});
};

// 4) ГЕО/ПУЛ — повертаємо jqXHR
window.critFetchGeoBatch = function(){
var ips = [];
$('td.crit-geo[data-ip], td.crit-pool[data-ip]').each(function(){
var ip = $(this).data('ip');
if (ip && ips.indexOf(ip) === -1) ips.push(ip);
});
if (!ips.length){
return $.Deferred().resolve().promise();
}

return $.post(ajaxurl, {
action: 'critical_logger_geo_batch',
nonce: '<?php echo wp_create_nonce("critical_logger_simple_nonce"); ?>',
ips: ips
}).done(function(resp){
if (resp && resp.success && resp.data) {
	 Object.keys(resp.data).forEach(function(ip){
	 var info = resp.data[ip] || {};
	 // Відмалювати у клітинках
	 $('td.crit-pool[data-ip="'+ip+'"]').html(info.pool ? $('<span/>').text(info.pool) : '<em style="color:#888">—</em>');
	 $('td.crit-geo[data-ip="'+ip+'"]').html(info.geo? $('<span/>').text(info.geo): '<em style="color:#888">—</em>');

	 // ПІДСТАВИТИ значення у форму "Блокувати пул"
	 var $form = $('form.js-block-pool-form[data-ip="'+ip+'"]');
	 if ($form.length){
	 // якщо повернувся список через кому — беремо перший (сервер парсить один діапазон/ CIDR/ IP за раз)
	 var poolVal = (info.pool || '').split(',')[0].trim();
	 // якщо пул не отримали — підстрахуємося одиночним IP
	 if (!poolVal) poolVal = ip;

	 $form.find('input.js-pool-input').val(poolVal);
	 // розблокувати кнопку
	 $form.find('input.js-block-pool').prop('disabled', false);
	 }
	 });
}
});
};

// 5) Оновити все (чекаємо всі проміси; гео/пул викликається зсередини critFetchDetectedIPs)
function refreshAll(){
	return $.when(
		window.critFetchLogTable(500),
		window.critFetchDetectedIPs()
	);
}

// 6) Один-єдиний хендлер на кнопку
$('#crit-reload-logs').off('click').on('click', function(e){
	e.preventDefault();
	var $btn = $(this).prop('disabled', true).text('Оновлення...');
	refreshAll().always(function(){
	$btn.prop('disabled', false).text('Оновити');
	});
});

// 7) Автозавантаження при вході
$(function(){
	refreshAll();
});

})(jQuery);
</script>

	<?php

	if (ob_get_level()) ob_end_flush();
}
if (file_exists(plugin_dir_path(__FILE__) . 'critical-logger-intel-admin.php')) {
	require_once plugin_dir_path(__FILE__) . 'critical-logger-intel-admin.php';
}
if (file_exists(plugin_dir_path(__FILE__) . 'critical-logger-analytics.php')) {
	require_once plugin_dir_path(__FILE__) . 'critical-logger-analytics.php';
}
if (file_exists(plugin_dir_path(__FILE__) . 'critical-logger-ai.php')) {
	require_once plugin_dir_path(__FILE__) . 'critical-logger-ai.php';
}
// Підключення GeoBlock
if (file_exists(plugin_dir_path(__FILE__) . 'critical-logger-geoblock.php')) {
	require_once plugin_dir_path(__FILE__) . 'critical-logger-geoblock.php';
}
// === Ротація логів (автоочищення та архівація) ===
if (file_exists(plugin_dir_path(__FILE__) . 'critical-logger-rotation.php')) {
	require_once plugin_dir_path(__FILE__) . 'critical-logger-rotation.php';
}
// Settings page (API keys)
if (file_exists(plugin_dir_path(__FILE__) . 'critical-logger-seting.php')) {
	require_once plugin_dir_path(__FILE__) . 'critical-logger-seting.php';
}