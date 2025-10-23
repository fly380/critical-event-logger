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
$intel_core = plugin_dir_path(__FILE__) . 'intel.php';
if (file_exists($intel_core)) require_once $intel_core;

/* 2) AJAX: таблиця інтел-аналізу (окремо від головної сторінки) */
add_action('wp_ajax_critical_logger_intel_table', function () {
	if (!current_user_can('manage_options')) wp_send_json_error('Недостатньо прав', 403);
	check_ajax_referer('critical_logger_simple_nonce', 'nonce');

	$log_file = crit_log_file();
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
		'critical-event-logs',
		'Інтел-аналіз IP',
		'Інтел-аналіз',
		'manage_options',
		'critical-logger-intel-admin',
		'crit_intel_admin_page'
	);
});

/* 5) Рендер сторінки інтел-аналізу (із вбудованою Info-модалкою) */
function crit_intel_admin_page() {
	$ajax  = admin_url('admin-ajax.php');
	$nonce = wp_create_nonce('critical_logger_simple_nonce');

	echo '<div class="wrap">';
	// Шапка з кнопкою Info
	echo '<div class="crit-admin-header" style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:8px;">';
	echo '<h1 style="margin:0;">🔎 Інтел-аналіз підозрілих IP</h1>';
	echo '<button id="crit-intel-info-open" type="button" class="button button-secondary" aria-haspopup="dialog" aria-expanded="false" aria-controls="crit-intel-info-modal">Info</button>';
	echo '</div>';
	?>
	<style id="crit-intel-info-modal-css">
		#crit-intel-info-modal[hidden]{display:none;}
		#crit-intel-info-modal{position:fixed;inset:0;z-index:100000;}
		#crit-intel-info-modal .crit-modal__backdrop{position:absolute;inset:0;background:rgba(0,0,0,.35);}
		#crit-intel-info-modal .crit-modal__dialog{
			position:relative;max-width:860px;margin:6vh auto;background:#fff;border-radius:8px;
			box-shadow:0 10px 30px rgba(0,0,0,.2);padding:20px 22px;outline:0;
		}
		#crit-intel-info-modal h2{margin:0 32px 10px 0;}
		#crit-intel-info-modal .crit-modal__body{line-height:1.55;max-height:65vh;overflow:auto;padding-right:2px;}
		#crit-intel-info-modal .crit-modal__close{
			position:absolute;right:12px;top:10px;border:0;background:transparent;font-size:22px;line-height:1;cursor:pointer;
		}
		#crit-intel-info-modal .crit-kbd{display:inline-block;border:1px solid #ddd;border-bottom-width:2px;border-radius:4px;padding:0 5px;font:12px/20px monospace;background:#f8f8f8}
		#crit-intel-info-modal ul{margin:0 0 10px 18px}
		#crit-intel-info-modal li{margin:6px 0}
		#crit-intel-info-modal code{background:#f6f7f7;border:1px solid #e2e4e7;border-radius:3px;padding:1px 4px}
	</style>

	<div id="crit-intel-info-modal" role="dialog" aria-modal="true" aria-labelledby="crit-intel-info-title" hidden>
		<div class="crit-modal__backdrop" data-close="1"></div>
		<div class="crit-modal__dialog" role="document" tabindex="-1">
			<button type="button" class="crit-modal__close" id="crit-intel-info-close" aria-label="Закрити" title="Закрити (Esc)">×</button>
			<h2 id="crit-intel-info-title">Що вміє модуль «Інтел-аналіз IP»</h2>
			<div class="crit-modal__body">
				<p><strong>Огляд функцій сторінки:</strong></p>
				<ul>
					<li><strong>Таблиця інтел-аналізу</strong> — проглядає увесь журнал, збирає всі IPv4, рахує частоту й сортує за спаданням.
						<ul>
							<li>Колонки: IP · Кількість · Оцінка (score) · Джерело · Стан.</li>
							<li>«Стан»: ✅ Безпечний або ❌ Підозрілий (див. правила нижче).</li>
						</ul>
					</li>
					<li><strong>Джерела даних</strong> (ключі з опцій/констант; якщо ключ порожній — джерело пропускається):
						<ul>
							<li><code>AbuseIPDB</code> — <code>crit_abuseipdb_key</code> / <code>CRIT_ABUSEIPDB_KEY</code> → <em>abuseConfidenceScore</em> (%).</li>
							<li><code>VirusTotal</code> — <code>crit_virustotal_key</code> / <code>CRIT_VIRUSTOTAL_KEY</code> → «детекти» (malicious/suspicious).</li>
							<li><code>CrowdSec</code> — <code>crit_crowdsec_key</code> / <code>CRIT_CROWDSEC_KEY</code> (авто-токен, кеш ~23год) → класифікації/атаки/фон.</li>
							<li><code>Spamhaus ZEN</code> — без ключа, DNSBL для IPv4.</li>
						</ul>
					</li>
					<li><strong>Формула score</strong>:
						<ul>
							<li>AbuseIPDB: +<code>abuseConfidenceScore</code> (0–100)</li>
							<li>VirusTotal: <code>детекти × 10</code></li>
							<li>Spamhaus: +30, якщо в списках</li>
							<li>CrowdSec: +40, якщо є збіг</li>
							<li>Кеп: максимум 150; підсвітка рядка: ≥60 — червоний, ≥20 — жовтий, інакше зелений.</li>
						</ul>
					</li>
					<li><strong>Коли «❌ Підозрілий»</strong>:
						<ul>
							<li>Будь-який явний негатив із VT/Spamhaus/CrowdSec, або</li>
							<li><em>score</em> ≥ 80, або <em>кілька джерел</em> з тригерами.</li>
						</ul>
					</li>
					<li><strong>Кешування</strong>:
						<ul>
							<li>Інтел-відповіді по IP: транзієнт на 12 год (<code>CRIT_INTEL_CACHE_TTL</code>).</li>
							<li>Токен CrowdSec: ~23 год (окремо на ключ).</li>
							<li>Кнопка «🧽 Очистити кеш інтел/гео/пул» — форсить свіже опитування.</li>
						</ul>
					</li>
					<li><strong>Кнопки сторінки</strong>:
						<ul>
							<li><em>Оновити</em> — AJAX-перезавантаження таблиці (<code>critical_logger_intel_table</code>).</li>
							<li><em>🧽 Очистити кеш…</em> — POST, що чистить інтел/гео/пул-кеші (показує нотифікацію).</li>
						</ul>
					</li>
					<li><strong>Приватність</strong>: назовні відправляються тільки IP та службові заголовки; ключі лежать у WP-опціях/константах. Ліміти API знімаються кешем.</li>
				</ul>
				<p><strong>Де задати ключі:</strong> <code>crit_abuseipdb_key</code>, <code>crit_virustotal_key</code>, <code>crit_crowdsec_key</code> (або їхні константи). Для AI — <code>crit_openai_key</code>/<code>CRIT_OPENAI_KEY</code>.</p>
				<p><span class="crit-kbd">Esc</span> — закрити модалку; клік поза вікном — також закриє.</p>
			</div>
		</div>
	</div>
	<?php

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

	// JS: завантаження таблиці та керування модалкою
	echo '<script>
	(function($){
		function loadIntel(){
			return $.post('.json_encode($ajax).', { action:"critical_logger_intel_table", nonce:'.json_encode($nonce).' })
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

		// === INFO MODAL ===
		var $modal    = $("#crit-intel-info-modal");
		var $dialog   = $modal.find(".crit-modal__dialog");
		var $openBtn  = $("#crit-intel-info-open");
		var $closeBtn = $("#crit-intel-info-close");
		var lastFocus = null;

		function openModal(){
			lastFocus = document.activeElement;
			$modal.removeAttr("hidden");
			$openBtn.attr("aria-expanded","true");
			setTimeout(function(){ $dialog.trigger("focus"); }, 0);
		}
		function closeModal(){
			$modal.attr("hidden","hidden");
			$openBtn.attr("aria-expanded","false");
			if (lastFocus) { lastFocus.focus(); }
		}
		$openBtn.on("click", function(e){ e.preventDefault(); openModal(); });
		$closeBtn.on("click", function(){ closeModal(); });
		$modal.on("click", function(e){
			if ($(e.target).is("[data-close], .crit-modal__backdrop")) { closeModal(); }
		});
		$(document).on("keydown", function(e){
			if (e.key === "Escape" && !$modal.is("[hidden]")) { e.preventDefault(); closeModal(); }
		});
	})(jQuery);
	</script>';

	echo '</div>';
}
