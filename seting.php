<?php
/**
 * Critical Event Logger — helper module
 * Copyright © 2025 Казмірчук Андрій
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */
if (!defined('ABSPATH')) exit;

/* ---------------- Хелпери ---------------- */

function crit_mask_key($k) {
	if (empty($k)) return '';
	$len = strlen($k);
	if ($len <= 12) return substr($k, 0, 3) . '...' . substr($k, -3);
	return substr($k, 0, 6) . '...' . substr($k, -6);
}

/** ЄДИНИЙ геттер — читаємо ЛИШЕ з БД */
function crit_get_api_key_value(string $option_name): string {
	return trim((string) get_option($option_name, ''));
}

/** Для UI (джерело завжди DB або '') */
function crit_get_api_key_with_source(string $option_name): array {
	$val = crit_get_api_key_value($option_name);
	return $val !== '' ? ['value' => $val, 'source' => 'db'] : ['value' => '', 'source' => ''];
}

/* Очищення транзієнтів */
function crit_delete_transients_by_prefix(string $prefix): void {
	global $wpdb;
	$like_main = $wpdb->esc_like('_transient_' . $prefix) . '%';
	$like_to   = $wpdb->esc_like('_transient_timeout_' . $prefix) . '%';
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options}
			 WHERE option_name LIKE %s OR option_name LIKE %s",
			$like_main, $like_to
		)
	);
}

function crit_purge_all_intel_caches(): void {
	crit_delete_transients_by_prefix('crit_intel_'); // інтел-результати
	crit_delete_transients_by_prefix('crit_geo_');   // гео
	crit_delete_transients_by_prefix('crit_pool_');  // RDAP/RIPE/WHOIS пул
}

/* ---------------- Меню ---------------- */

add_action('admin_menu', function () {
	add_submenu_page(
		'critical-event-logs',
		'Critical Logger — Ключі API',
		'API Keys',
		'manage_options',
		'critical-logger-keys',
		'crit_keys_settings_page'
	);
});

/* ---------------- Сторінка ---------------- */

function crit_keys_settings_page() {
	if (!current_user_can('manage_options')) wp_die('Недостатньо прав');

	$notice = '';

	/* ======= Дії до збереження ======= */

	// 1) Очистити конкретний ключ (БД)
	if (isset($_POST['crit_key_action']) && $_POST['crit_key_action'] === 'clear_db') {
		check_admin_referer('crit_keys_actions', 'crit_keys_nonce');

		$map = [
			'abuseipdb' => ['opt' => 'crit_abuseipdb_key', 'label' => 'AbuseIPDB'],
			'virustotal'=> ['opt' => 'crit_virustotal_key','label' => 'VirusTotal'],
			'crowdsec'  => ['opt' => 'crit_crowdsec_key',  'label' => 'CrowdSec'],
			'openai'    => ['opt' => 'crit_openai_key',    'label' => 'OpenAI'],
		];

		$key_id = sanitize_key($_POST['key_id'] ?? '');
		if (isset($map[$key_id])) {
			delete_option($map[$key_id]['opt']);
			$notice .= '<div class="notice notice-success"><p>🗑 Видалено з БД: ' . esc_html($map[$key_id]['label']) . '</p></div>';
			crit_purge_all_intel_caches();
			$notice .= '<div class="notice notice-info"><p>🧽 Очищено кеші інтел/гео/пул.</p></div>';
		} else {
			$notice .= '<div class="notice notice-error"><p>Невідомий ключ.</p></div>';
		}
	}

	// 2) Глобальне очищення кешу
	if (isset($_POST['crit_flush_caches'])) {
		check_admin_referer('crit_keys_actions', 'crit_keys_nonce');
		crit_purge_all_intel_caches();
		$notice .= '<div class="notice notice-success"><p>🧽 Кеш очищено: інтел/гео/пул.</p></div>';
	}

	/* ======= Збереження ключів у БД ======= */
	if (isset($_POST['crit_keys_save'])) {
		check_admin_referer('crit_keys_save_action', 'crit_keys_save_nonce');

		$in = [
			'abuseipdb' => sanitize_text_field($_POST['crit_abuseipdb_key'] ?? ''),
			'virustotal'=> sanitize_text_field($_POST['crit_virustotal_key'] ?? ''),
			'crowdsec'  => sanitize_text_field($_POST['crit_crowdsec_key'] ?? ''),
			'openai'    => sanitize_text_field($_POST['crit_openai_key'] ?? ''),
		];

		// Пишемо лише непорожні значення (щоб випадкове порожнє не затерло існуючий ключ)
		if ($in['abuseipdb'] !== '') update_option('crit_abuseipdb_key', $in['abuseipdb']);
		if ($in['virustotal'] !== '') update_option('crit_virustotal_key', $in['virustotal']);
		if ($in['crowdsec']   !== '') update_option('crit_crowdsec_key',   $in['crowdsec']);
		if ($in['openai']     !== '') update_option('crit_openai_key',     $in['openai']);

		$notice .= '<div class="notice notice-success"><p>✅ Налаштування збережено у БД.</p></div>';

		// Після змін ключів — очистити кеш, щоб інтел одразу підхопив нові значення
		crit_purge_all_intel_caches();
		$notice .= '<div class="notice notice-info"><p>🧽 Очищено кеші інтел/гео/пул.</p></div>';
	}

	/* ======= Поточний стан ======= */
	$keys = [
		'abuseipdb' => crit_get_api_key_with_source('crit_abuseipdb_key'),
		'virustotal'=> crit_get_api_key_with_source('crit_virustotal_key'),
		'crowdsec'  => crit_get_api_key_with_source('crit_crowdsec_key'),
		'openai'    => crit_get_api_key_with_source('crit_openai_key'),
	];

	$badge = function($source) {
		if ($source === 'db') return ' <span class="dashicons dashicons-database"></span> <em style="color:#555;">DB</em>';
		return ' <em style="color:#888;">(не задано)</em>';
	};

	echo '<div class="wrap">';
	echo '<h1>🔐 Critical Logger — API Keys</h1>';
	echo $notice;

	/* ======= Форма збереження ======= */
	echo '<form method="post" action="">';
	wp_nonce_field('crit_keys_save_action', 'crit_keys_save_nonce');

	echo '<table class="form-table">';

	// AbuseIPDB
	echo '<tr><th>
			<label for="crit_abuseipdb_key">AbuseIPDB API Key</label><br>
			<a class="button button-small" target="_blank" rel="noopener noreferrer" href="https://www.abuseipdb.com/account/api">Отримати ключ</a>
		</th><td>';
	echo '<input type="text" id="crit_abuseipdb_key" name="crit_abuseipdb_key" value="" style="width:420px;" autocomplete="off">';
	if ($keys['abuseipdb']['value'] !== '') {
		echo '<p class="description">Збережено: <code>' . esc_html(crit_mask_key($keys['abuseipdb']['value'])) . '</code>' . $badge($keys['abuseipdb']['source']) . '</p>';
	} else {
		echo '<p class="description">Введи ключ і натисни “Зберегти”.</p>';
	}
	echo '</td></tr>';

	// VirusTotal
	echo '<tr><th>
			<label for="crit_virustotal_key">VirusTotal API Key</label><br>
			<a class="button button-small" target="_blank" rel="noopener noreferrer" href="https://www.virustotal.com/gui/my-apikey">Отримати ключ</a>
		</th><td>';
	echo '<input type="text" id="crit_virustotal_key" name="crit_virustotal_key" value="" style="width:420px;" autocomplete="off">';
	if ($keys['virustotal']['value'] !== '') {
		echo '<p class="description">Збережено: <code>' . esc_html(crit_mask_key($keys['virustotal']['value'])) . '</code>' . $badge($keys['virustotal']['source']) . '</p>';
	} else {
		echo '<p class="description">Введи ключ і натисни “Зберегти”.</p>';
	}
	echo '</td></tr>';

	// CrowdSec
	echo '<tr><th>
			<label for="crit_crowdsec_key">CrowdSec API Key</label><br>
			<a class="button button-small" target="_blank" rel="noopener noreferrer" href="https://app.crowdsec.net/">Створити/переглянути ключ</a>
		</th><td>';
	echo '<input type="text" id="crit_crowdsec_key" name="crit_crowdsec_key" value="" style="width:420px;" autocomplete="off">';
	if ($keys['crowdsec']['value'] !== '') {
		echo '<p class="description">Збережено: <code>' . esc_html(crit_mask_key($keys['crowdsec']['value'])) . '</code>' . $badge($keys['crowdsec']['source']) . '</p>';
	} else {
		echo '<p class="description">Введи ключ і натисни “Зберегти”.</p>';
	}
	echo '</td></tr>';

	// OpenAI
	echo '<tr><th>
			<label for="crit_openai_key">OpenAI API Key</label><br>
			<a class="button button-small" target="_blank" rel="noopener noreferrer" href="https://platform.openai.com/api-keys">Отримати ключ</a>
		</th><td>';
	echo '<input type="text" id="crit_openai_key" name="crit_openai_key" value="" style="width:420px;" autocomplete="off">';
	if ($keys['openai']['value'] !== '') {
		echo '<p class="description">Збережено: <code>' . esc_html(crit_mask_key($keys['openai']['value'])) . '</code>' . $badge($keys['openai']['source']) . '</p>';
	} else {
		echo '<p class="description">Введи ключ і натисни “Зберегти”.</p>';
	}
	echo '</td></tr>';

	echo '</table>';

	echo '<p><input type="submit" name="crit_keys_save" class="button button-primary" value="💾 Зберегти"></p>';
	echo '</form>';

	/* ======= Блок “Очистити ключі (БД)” + “Очистити кеш” ======= */
	echo '<h2 style="margin-top:24px;">🧹 Сервісні дії</h2>';
	echo '<p class="description">Ключі зберігаються тільки у БД. Тут можна видалити окремий ключ та очистити кеш інтел/гео/пул.</p>';

	echo '<table class="widefat striped" style="max-width:800px">';
	echo '<thead><tr><th>Сервіс</th><th>Поточний стан</th><th style="width:260px">Дії</th></tr></thead><tbody>';

	$rows = [
		['id' => 'abuseipdb', 'label' => 'AbuseIPDB', 'k' => $keys['abuseipdb']],
		['id' => 'virustotal','label' => 'VirusTotal','k' => $keys['virustotal']],
		['id' => 'crowdsec',  'label' => 'CrowdSec',  'k' => $keys['crowdsec']],
		['id' => 'openai',    'label' => 'OpenAI',    'k' => $keys['openai']],
	];

	foreach ($rows as $r) {
		echo '<tr>';
		echo '<td><strong>' . esc_html($r['label']) . '</strong></td>';
		if ($r['k']['value'] !== '') {
			echo '<td><code>' . esc_html(crit_mask_key($r['k']['value'])) . '</code> <span class="dashicons dashicons-database"></span> <em style="color:#555;">DB</em></td>';
		} else {
			echo '<td><em style="color:#888;">(не задано)</em></td>';
		}
		echo '<td>';
			echo '<form method="post" style="display:inline">';
			wp_nonce_field('crit_keys_actions','crit_keys_nonce', true, true);
			echo '<input type="hidden" name="key_id" value="' . esc_attr($r['id']) . '">';
			echo '<button class="button" name="crit_key_action" value="clear_db" onclick="return confirm(\'Видалити ключ ' . esc_attr($r['label']) . ' з БД?\');">Очистити ключ (БД)</button>';
			echo '</form>';
		echo '</td>';
		echo '</tr>';
	}
	echo '</tbody></table>';

	// ОДНА глобальна кнопка “Очистити кеш”
	echo '<form method="post" style="margin-top:12px;">';
	wp_nonce_field('crit_keys_actions','crit_keys_nonce', true, true);
	echo '<input type="hidden" name="crit_flush_caches" value="1">';
	echo '<button class="button button-secondary">🧽 Очистити кеш інтел/гео/пул</button>';
	echo '</form>';

	echo '<hr><p style="color:#666">Під час роботи модуль читає ключі ТІЛЬКИ з БД.</p>';
	echo '</div>';
}
