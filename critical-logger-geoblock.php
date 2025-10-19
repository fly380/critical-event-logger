<?php
/**
 * Critical Event Logger — helper module
 * Copyright © 2025 Казмірчук Андрій
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if (!defined('ABSPATH')) exit;

/* ============================================================
 * GEO BLOCK — Блокування або дозвіл доступу за країною
 * ============================================================ */

/**
 * Отримати список країн із налаштувань
 */
function crit_geoblock_get_countries() {
	$countries = get_option('crit_geoblock_countries', ['RU', 'CN', 'KP']);
	return array_map('strtoupper', (array)$countries);
}

/**
 * Визначити країну IP через ipwho.is (з fallback на ip-api)
 */
function crit_geoblock_get_country($ip) {
	if (!filter_var($ip, FILTER_VALIDATE_IP)) return '';

	$cache_key = 'crit_geo_country_' . md5($ip);
	$cached = get_transient($cache_key);
	if ($cached !== false) return $cached;

	$country = '';

	// === Основне джерело: ipwho.is ===
	$resp = wp_remote_get("https://ipwho.is/{$ip}", ['timeout' => 8]);
	if (!is_wp_error($resp)) {
		$body = wp_remote_retrieve_body($resp);
		$data = json_decode($body, true);
		if (!empty($data['success']) && !empty($data['country_code'])) {
			$country = strtoupper($data['country_code']);
		}
	}

	// === Резервне джерело: ip-api ===
	if (empty($country)) {
		$fallback = wp_remote_get("http://ip-api.com/json/{$ip}?fields=status,countryCode", ['timeout' => 8]);
		if (!is_wp_error($fallback)) {
			$fb_data = json_decode(wp_remote_retrieve_body($fallback), true);
			if (!empty($fb_data['status']) && $fb_data['status'] === 'success') {
				$country = strtoupper($fb_data['countryCode']);
			}
		}
	}

	// === Якщо нічого не знайшли — ставимо UNKNOWN ===
	if (empty($country)) $country = '??';

	// === Кешуємо на 12 год ===
	set_transient($cache_key, $country, 12 * HOUR_IN_SECONDS);
	return $country;
}

/**
 * Основна логіка GeoBlock
 */
add_action('init', function() {
	if (is_admin()) return;
	if (defined('DOING_AJAX') && DOING_AJAX) return;
	if (current_user_can('manage_options')) return;

	$enabled = get_option('crit_geoblock_enabled', false);
	if (!$enabled) return;

	$reverse_mode = get_option('crit_geoblock_reverse', false);
	$ip = $_SERVER['REMOTE_ADDR'] ?? '';
	if (empty($ip)) return;

	$country = crit_geoblock_get_country($ip);
	$list = crit_geoblock_get_countries();
	$should_block = false;

	if ($reverse_mode) {
		// Дозволені лише ці країни
		if (!in_array($country, $list, true)) {
			$should_block = true;
		}
	} else {
		// Заборонені ці країни
		if (in_array($country, $list, true)) {
			$should_block = true;
		}
	}

	if ($should_block) {
		// === Логування ===
		$log_file = plugin_dir_path(__FILE__) . 'logs/events.log';
		$entry = '[' . date('Y-m-d H:i:s') . "][GeoBlock][$country][WARN] Заблоковано вхід з країни $country ($ip)\n";
		@file_put_contents($log_file, $entry, FILE_APPEND | LOCK_EX);

		// === Відповідь користувачу ===
		header('HTTP/1.1 403 Forbidden');
		wp_die(
			'<h1>⛔ Доступ заборонено</h1><p>Ваш IP (' . esc_html($ip) . ') з країни ' . esc_html($country) . ' не має доступу до сайту.</p>',
			'GeoBlock',
			['response' => 403]
		);
		exit;
	}
});

/* ============================================================
 * СТОРІНКА НАЛАШТУВАНЬ GEO BLOCK
 * ============================================================ */
add_action('admin_menu', function() {
	add_submenu_page(
		'critical-event-logs',
		'GeoBlock — Географічне блокування',
		'GeoBlock',
		'manage_options',
		'critical-geoblock',
		'crit_geoblock_settings_page'
	);
});

function crit_geoblock_settings_page() {
	if (isset($_POST['crit_geoblock_save'])) {
		check_admin_referer('crit_geoblock_save_action', 'crit_geoblock_nonce');

		$enabled = !empty($_POST['crit_geoblock_enabled']);
		$reverse = !empty($_POST['crit_geoblock_reverse']);
		$countries_raw = strtoupper(trim($_POST['crit_geoblock_countries'] ?? ''));
		$countries = array_filter(array_map('trim', explode(',', $countries_raw)));

		update_option('crit_geoblock_enabled', $enabled);
		update_option('crit_geoblock_reverse', $reverse);
		update_option('crit_geoblock_countries', $countries);

		echo '<div class="notice notice-success"><p>✅ Налаштування GeoBlock збережено.</p></div>';
	}

	$enabled = get_option('crit_geoblock_enabled', false);
	$reverse = get_option('crit_geoblock_reverse', false);
	$countries = implode(', ', get_option('crit_geoblock_countries', ['RU', 'CN', 'KP']));

	echo '<div class="wrap"><h1>🌍 GeoBlock — Географічне блокування</h1>';
	echo '<form method="post">';
	wp_nonce_field('crit_geoblock_save_action', 'crit_geoblock_nonce');

	echo '<p><label><input type="checkbox" name="crit_geoblock_enabled" value="1" ' . checked($enabled, true, false) . '> 
		<strong>Увімкнути GeoBlock</strong></label></p>';

	echo '<p><label><input type="checkbox" name="crit_geoblock_reverse" value="1" ' . checked($reverse, true, false) . '> 
		Режим “дозволені країни” (інші блокуються)</label></p>';

	echo '<p><label>Коди країн (через кому, наприклад <code>UA, PL, US</code>):<br>';
	echo '<input type="text" name="crit_geoblock_countries" value="' . esc_attr($countries) . '" style="width:400px;"></label></p>';

	echo '<p><input type="submit" name="crit_geoblock_save" class="button-primary" value="💾 Зберегти"></p>';

	echo '<hr><p style="color:#666;">GeoBlock використовує <code>ipwho.is</code> як основне джерело геолокації та <code>ip-api.com</code> як запасне. 
	Дані кешуються на 12 годин для стабільності. GeoBlock не змінює .htaccess, тож у разі блокування просто вимкни плагін через FTP.</p>';

	echo '</form></div>';
}
