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
		$entry = '[' . crit_log_time() . "][GeoBlock][$country][WARN] Заблоковано вхід з країни $country ($ip)\n";
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

	echo '<div class="wrap">';
echo '<div class="crit-admin-header" style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:8px;">';
echo '<h1 style="margin:0;">🌍 GeoBlock — Географічне блокування</h1>';
echo '<button id="crit-geo-info-open" type="button" class="button button-secondary" aria-haspopup="dialog" aria-expanded="false" aria-controls="crit-geo-info-modal">Info</button>';
echo '</div>';
?>
<style id="crit-geo-info-modal-css">
	#crit-geo-info-modal[hidden]{display:none;}
	#crit-geo-info-modal{position:fixed;inset:0;z-index:100000;}
	#crit-geo-info-modal .crit-modal__backdrop{position:absolute;inset:0;background:rgba(0,0,0,.35);}
	#crit-geo-info-modal .crit-modal__dialog{
		position:relative;max-width:820px;margin:6vh auto;background:#fff;border-radius:8px;
		box-shadow:0 10px 30px rgba(0,0,0,.2);padding:20px 22px;outline:0;
	}
	#crit-geo-info-modal h2{margin:0 32px 10px 0;}
	#crit-geo-info-modal .crit-modal__body{line-height:1.55;max-height:65vh;overflow:auto;padding-right:2px;}
	#crit-geo-info-modal .crit-modal__close{
		position:absolute;right:12px;top:10px;border:0;background:transparent;font-size:22px;line-height:1;cursor:pointer;
	}
	#crit-geo-info-modal .crit-kbd{display:inline-block;border:1px solid #ddd;border-bottom-width:2px;border-radius:4px;padding:0 5px;font:12px/20px monospace;background:#f8f8f8}
	#crit-geo-info-modal ul{margin:0 0 10px 18px}
	#crit-geo-info-modal li{margin:6px 0}
	#crit-geo-info-modal code{background:#f6f7f7;border:1px solid #e2e4e7;border-radius:3px;padding:1px 4px}
</style>
<div id="crit-geo-info-modal" role="dialog" aria-modal="true" aria-labelledby="crit-geo-info-title" hidden>
	<div class="crit-modal__backdrop" data-close="1"></div>
	<div class="crit-modal__dialog" role="document" tabindex="-1">
		<button type="button" class="crit-modal__close" id="crit-geo-info-close" aria-label="Закрити" title="Закрити (Esc)">×</button>
		<h2 id="crit-geo-info-title">Як працює GeoBlock</h2>
		<div class="crit-modal__body">
			<ul>
				<li><strong>Увімкнення</strong> — прапорець «Увімкнути GeoBlock» активує перевірку для фронтенду (адміни та AJAX оминаються).</li>
				<li><strong>Режим</strong>:
					<ul>
						<li>Стандартний — <em>blacklist</em>: країни зі списку блокуються.</li>
						<li>«Дозволені країни» — <em>whitelist</em>: доступ лише країнам зі списку, решта блокуються.</li>
					</ul>
				</li>
				<li><strong>Коди країн</strong> — ISO&nbsp;3166-1 alpha-2, через кому (напр. <code>UA, PL, US</code>). Пробіли і регістр неважливі.</li>
				<li><strong>Визначення країни</strong> — основне джерело <code>ipwho.is</code>, резервне <code>ip-api.com</code>; кеш результату на 12 год.</li>
				<li><strong>Логування</strong> — при блокуванні додається рядок у <code>logs/events.log</code> з тегом <code>[GeoBlock]</code> і рівнем <code>WARN</code>.</li>
				<li><strong>Відповідь</strong> — користувач отримує <code>403 Forbidden</code> із коротким повідомленням.</li>
				<li><strong>Інфраструктура</strong> — перевіряється <code>$_SERVER['REMOTE_ADDR']</code>. Якщо сайт за CDN/проксі (Cloudflare/NGINX), переконайся, що REMOTE_ADDR — це IP клієнта, або адаптуй отримання IP у своєму хоку.</li>
				<li><strong>Безпека</strong> — GeoBlock не змінює <code>.htaccess</code>; у разі надмірного блокування можна просто вимкнути плагін через FTP.</li>
			</ul>
			<p><span class="crit-kbd">Esc</span> — закрити; клік по затемненню — теж закриє.</p>
		</div>
	</div>
</div>
<?php

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

	echo '</form>';
	?>
<script>
// === INFO MODAL (GeoBlock page) ===
(function($){
	var $modal    = $('#crit-geo-info-modal');
	var $dialog   = $modal.find('.crit-modal__dialog');
	var $openBtn  = $('#crit-geo-info-open');
	var $closeBtn = $('#crit-geo-info-close');
	var lastFocus = null;

	function openModal(){
		lastFocus = document.activeElement;
		$modal.removeAttr('hidden');
		$openBtn.attr('aria-expanded','true');
		setTimeout(function(){ $dialog.trigger('focus'); }, 0);
	}
	function closeModal(){
		$modal.attr('hidden','hidden');
		$openBtn.attr('aria-expanded','false');
		if (lastFocus) { lastFocus.focus(); }
	}

	$openBtn.on('click', function(e){ e.preventDefault(); openModal(); });
	$closeBtn.on('click', function(){ closeModal(); });
	$modal.on('click', function(e){
		if ($(e.target).is('[data-close], .crit-modal__backdrop')) { closeModal(); }
	});
	$(document).on('keydown', function(e){
		if (e.key === 'Escape' && !$modal.is('[hidden]')) { e.preventDefault(); closeModal(); }
	});
})(jQuery);
</script>
<?php

	echo '</div>';
}
