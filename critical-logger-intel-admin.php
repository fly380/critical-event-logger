<?php
/**
 * Critical Event Logger — helper module
 * Copyright © 2025 Казмірчук Андрій
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */
// critical-logger-intel-admin.php
if (!defined('ABSPATH')) exit;

/* 1) Підключаємо функціонал інтел-аналізу */
$intel_core = plugin_dir_path(__FILE__) . 'critical-logger-intel.php';
if (file_exists($intel_core)) require_once $intel_core;

/* 2) AJAX: таблиця інтел-аналізу (окремо від головної сторінки) */
add_action('wp_ajax_critical_logger_intel_table', function () {
	if (!current_user_can('manage_options')) wp_send_json_error('Недостатньо прав', 403);
	check_ajax_referer('critical_logger_simple_nonce', 'nonce');

	$log_file = plugin_dir_path(__FILE__) . 'logs/events.log';
	if (!file_exists($log_file)) wp_send_json_error('Лог-файл не знайдено', 404);

	$all_lines = file($log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
	$ip_counts = [];
	foreach ($all_lines as $ln) {
		if (preg_match('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $ln, $m)) {
			$ip_counts[$m[0]] = ($ip_counts[$m[0]] ?? 0) + 1;
		}
	}
	arsort($ip_counts);

	ob_start();
	echo '<table class="widefat striped" style="width:100%;">';
	echo '<thead><tr>
		<th>IP</th><th>Кількість</th><th>Оцінка</th><th>Джерело</th><th>Стан</th>
	</tr></thead><tbody>';

	if (function_exists('crit_check_ip_intel')) {
		foreach ($ip_counts as $ip => $cnt) {
			$intel = crit_check_ip_intel($ip);
			$score = intval($intel['score']);
			$is_bad = !empty($intel['is_malicious']);

			$details = [];
			if (!empty($intel['abuseipdb'])) $details[] = 'AbuseIPDB (' . $intel['abuseipdb'] . '%)';
			if (!empty($intel['virustotal'])) $details[] = 'VirusTotal (' . $intel['virustotal'] . ' детектів)';
			if (!empty($intel['spamhaus'])) $details[] = 'Spamhaus';
			if (!empty($intel['crowdsec'])) $details[] = 'CrowdSec';
			$details_str = $details ? implode(', ', $details) : '-';

			$row_style = $score >= 60 ? 'background:#ffd7d7;' : ($score >= 20 ? 'background:#fff4cc;' : 'background:#eaffea;');

			echo '<tr style="' . esc_attr($row_style) . '">';
			echo '<td>' . esc_html($ip) . '</td>';
			echo '<td>' . intval($cnt) . '</td>';
			echo '<td class="crit-score-cell">' . esc_html($score) . '</td>';
			echo '<td>' . esc_html($details_str) . '</td>';
			echo '<td>' . ($is_bad ? '❌ Підозрілий' : '✅ Безпечний') . '</td>';
			echo '</tr>';
		}
	} else {
		echo '<tr><td colspan="5">Інтел-модуль недоступний.</td></tr>';
	}

	echo '</tbody></table>';
	$html = ob_get_clean();
	wp_send_json_success(['html' => $html]);
});

/* 3) Кнопка «Очистити кеш» — POST на цій сторінці */
add_action('admin_init', function () {
	if (!is_admin()) return;
	if (!current_user_can('manage_options')) return;

	if (isset($_POST['crit_purge_intel_cache'])) {
		check_admin_referer('crit_purge_intel_cache_action', 'crit_purge_intel_cache_nonce');
		if (function_exists('crit_purge_all_intel_caches')) {
			crit_purge_all_intel_caches();
		}
		add_action('admin_notices', function () {
			echo '<div class="notice notice-success"><p>🧽 Кеш інтел/гео/пул очищено.</p></div>';
		});
	}
});

/* 4) Додаємо сторінку-меню як у «Ротація логів» */
add_action('admin_menu', function () {
	add_submenu_page(
		'critical-event-logs',                 // той самий parent slug, що й головна
		'Інтел-аналіз IP',                     // заголовок сторінки
		'Інтел-аналіз',                        // назва в меню
		'manage_options',                      // capability
		'critical-logger-intel-admin',         // slug (URL ?page=critical-logger-intel-admin)
		'crit_intel_admin_page'                // callback
	);
});

/* 5) Рендер сторінки інтел-аналізу */
function crit_intel_admin_page() {
	$ajax = admin_url('admin-ajax.php');
	$nonce = wp_create_nonce('critical_logger_simple_nonce');

	echo '<div class="wrap">';
	echo '<h1>🔎 Інтел-аналіз підозрілих IP</h1>';

	// Кнопка очистки кешу
	echo '<form method="post" style="margin:12px 0;">';
	wp_nonce_field('crit_purge_intel_cache_action', 'crit_purge_intel_cache_nonce');
	echo '<input type="submit" class="button" name="crit_purge_intel_cache" value="🧽 Очистити кеш інтел/гео/пул">';
	echo '</form>';

	// Контейнер таблиці
	echo '<div id="crit-intel-container" style="max-height:520px; overflow-y:auto; border:1px solid #ddd; border-radius:6px; background:#fff; padding:6px;">';
	echo '<div style="padding:12px; color:#666;">Завантаження інтел-даних…</div>';
	echo '</div>';

	// Кнопка оновлення
	echo '<p style="margin-top:10px;"><button id="crit-intel-refresh" class="button">Оновити</button></p>';

	// JS завантаження таблиці
	echo '<script>
	(function($){
		function loadIntel(){
			return $.post("'.esc_js($ajax).'", { action:"critical_logger_intel_table", nonce:"'.esc_js($nonce).'" })
			.done(function(resp){
				if(resp && resp.success && resp.data && resp.data.html){
					$("#crit-intel-container").html(resp.data.html);
				}else{
					$("#crit-intel-container").html(\'<div style="padding:12px;color:#c00;">Не вдалося завантажити інтел-дані.</div>\');
				}
			})
			.fail(function(){
				$("#crit-intel-container").html(\'<div style="padding:12px;color:#c00;">Помилка AJAX-запиту при завантаженні інтел-даних.</div>\');
			});
		}
		$("#crit-intel-refresh").on("click", function(e){
			e.preventDefault();
			var $b=$(this).prop("disabled", true).text("Оновлення...");
			loadIntel().always(function(){ $b.prop("disabled", false).text("Оновити"); });
		});
		$(function(){ loadIntel(); });
	})(jQuery);
	</script>';

	echo '</div>';
}
