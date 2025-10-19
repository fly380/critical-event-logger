<?php
/**
 * Critical Event Logger — helper module
 * Copyright © 2025 Казмірчук Андрій
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */
if (!defined('ABSPATH')) exit;

/**
 * Critical Logger — сторінка аналітики (дашборд)
 */

add_action('admin_menu', function() {
	add_submenu_page(
		'critical-event-logs',
		'Аналітика безпеки',
		'Аналітика',
		'manage_options',
		'critical-logger-analytics',
		'critical_logger_analytics_page'
	);
});

function critical_logger_analytics_page() {
	echo '<div class="wrap"><h1>📊 Аналітика безпеки</h1>';
	echo '<div id="crit-analytics-root" style="min-height:400px;"></div>';
	echo '</div>';

	// Підключаємо Chart.js
	wp_enqueue_script(
		'chartjs',
		'https://cdn.jsdelivr.net/npm/chart.js',
		[],
		'4.4.1',
		true
	);

	// JS дашборду
	wp_enqueue_script(
		'crit-analytics-js',
		plugin_dir_url(__FILE__) . 'js/critical-analytics.js',
		['jquery', 'chartjs'],
		'1.0',
		true
	);

	wp_localize_script('crit-analytics-js', 'critAnalyticsData', [
		'ajaxUrl' => admin_url('admin-ajax.php'),
		'nonce'   => wp_create_nonce('crit_analytics_nonce')
	]);
}

/**
 * AJAX — дані для графіків
 */
add_action('wp_ajax_crit_get_analytics_data', 'crit_get_analytics_data_callback');

function crit_get_analytics_data_callback() {
	check_ajax_referer('crit_analytics_nonce', 'nonce');

	$log_file = plugin_dir_path(__FILE__) . 'logs/events.log';
	if (!file_exists($log_file)) {
		wp_send_json_error('Файл логів не знайдено');
	}

	$lines = file($log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
	$by_day = [];
	$by_country = [];
	$by_ip = [];

	foreach ($lines as $line) {
		if (preg_match('/^\[(\d{4}-\d{2}-\d{2})/', $line, $m)) {
			$date = $m[1];
			$by_day[$date] = ($by_day[$date] ?? 0) + 1;
		}

		if (preg_match('/\b(\d{1,3}\.){3}\d{1,3}\b/', $line, $m)) {
			$ip = $m[0];
			$by_ip[$ip] = ($by_ip[$ip] ?? 0) + 1;

			$geo_cache = get_transient('crit_geo_' . md5($ip));
			if (!empty($geo_cache['country'])) {
				$country = $geo_cache['country'];
				$by_country[$country] = ($by_country[$country] ?? 0) + 1;
			}
		}
	}

	ksort($by_day);
	arsort($by_ip);
	arsort($by_country);

	wp_send_json_success([
		'by_day'     => $by_day,
		'by_country' => array_slice($by_country, 0, 10, true),
		'by_ip'      => array_slice($by_ip, 0, 10, true),
	]);
}
