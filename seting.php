<?php
/**
 * Critical Event Logger — helper module (API Keys page + Info modal + Secret Reporter)
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
	crit_delete_transients_by_prefix('crit_intel_');           // інтел-результати
	crit_delete_transients_by_prefix('crit_geo_');             // гео
	crit_delete_transients_by_prefix('crit_pool_');            // RDAP/RIPE/WHOIS пул
	crit_delete_transients_by_prefix('crit_crowdsec_token_');  // LEGACY: токени CrowdSec (якщо колись були)
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
			// CrowdSec — повністю прибрано
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
			// 'crowdsec' повністю прибрано
			'openai'    => sanitize_text_field($_POST['crit_openai_key'] ?? ''),
		];

		// Пишемо лише непорожні значення (щоб випадкове порожнє не затерло існуючий ключ)
		if ($in['abuseipdb'] !== '') update_option('crit_abuseipdb_key', $in['abuseipdb']);
		if ($in['virustotal'] !== '') update_option('crit_virustotal_key', $in['virustotal']);
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
		// 'crowdsec'  — прибрано
		'openai'    => crit_get_api_key_with_source('crit_openai_key'),
	];

	$badge = function($source) {
		if ($source === 'db') return ' <span class="dashicons dashicons-database"></span> <em style="color:#555;">DB</em>';
		return ' <em style="color:#888;">(не задано)</em>';
	};

	echo '<div class="wrap">';
	// === Хедер із кнопкою Info ===
	echo '<div class="crit-admin-header" style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:8px;">';
	echo '<h1 style="margin:0;">🔐 Critical Logger — API Keys</h1>';
	echo '<button id="crit-keys-info-open" type="button" class="button button-secondary" aria-haspopup="dialog" aria-expanded="false" aria-controls="crit-keys-info-modal">Info</button>';
	echo '</div>';

	// === Модалка Info ===
	?>
	<style id="crit-keys-info-modal-css">
		#crit-keys-info-modal[hidden]{display:none;}
		#crit-keys-info-modal{position:fixed;inset:0;z-index:100000;}
		#crit-keys-info-modal .crit-modal__backdrop{position:absolute;inset:0;background:rgba(0,0,0,.35);}
		#crit-keys-info-modal .crit-modal__dialog{
			position:relative;max-width:820px;margin:6vh auto;background:#fff;border-radius:8px;
			box-shadow:0 10px 30px rgba(0,0,0,.2);padding:20px 22px;outline:0;
		}
		#crit-keys-info-modal h2{margin:0 32px 10px 0;}
		#crit-keys-info-modal .crit-modal__body{line-height:1.55;max-height:65vh;overflow:auto;padding-right:2px;}
		#crit-keys-info-modal .crit-modal__close{
			position:absolute;right:12px;top:10px;border:0;background:transparent;font-size:22px;line-height:1;cursor:pointer;
		}
		#crit-keys-info-modal ul{margin:0 0 10px 18px}
		#crit-keys-info-modal li{margin:6px 0}
		#crit-keys-info-modal code{background:#f6f7f7;border:1px solid #e2e4e7;border-radius:3px;padding:1px 4px}
	</style>
	<div id="crit-keys-info-modal" role="dialog" aria-modal="true" aria-labelledby="crit-keys-info-title" hidden>
		<div class="crit-modal__backdrop" data-close="1"></div>
		<div class="crit-modal__dialog" role="document" tabindex="-1">
			<button type="button" class="crit-modal__close" id="crit-keys-info-close" aria-label="Закрити" title="Закрити (Esc)">×</button>
			<h2 id="crit-keys-info-title">Про сторінку «API Keys»</h2>
			<div class="crit-modal__body">
				<ul>
					<li><strong>Джерело правди</strong> — ключі зберігаються <em>лише у БД</em>. Читання для UI: <code>crit_get_api_key_value()</code> / <code>crit_get_api_key_with_source()</code>.</li>
					<li><strong>Маскування</strong> — у відображенні значення обрізаються через <code>crit_mask_key()</code> (перші/останні 6 символів).</li>
					<li><strong>Збереження</strong> — кнопка «Зберегти» записує тільки <em>непорожні</em> поля, щоб випадкове порожнє значення не затерло чинний ключ.</li>
					<li><strong>Видалення ключа</strong> — у таблиці «Сервісні дії» кнопка «Очистити ключ (БД)» виконує <code>delete_option()</code> для вибраного сервісу.</li>
					<li><strong>Кеш</strong> — після змін/видалення ключів очищається кеш інтел/гео/пул (<code>crit_purge_all_intel_caches()</code>), щоб нові значення підхопилися відразу.</li>
					<li><strong>Глобальне очищення кешу</strong> — кнопка «🧽 Очистити кеш інтел/гео/пул» чистить транзієнти з префіксами <code>crit_intel_</code>, <code>crit_geo_</code>, <code>crit_pool_</code>.</li>
					<li><strong>Безпека</strong> — дії захищені <code>check_admin_referer()</code>; доступ мають тільки користувачі з правами <code>manage_options</code>.</li>
				</ul>
				<p><em>Порада:</em> після імпорту/міграції сайту перевір ключі та, за потреби, скористайся «Очистити кеш…», щоб уникнути застарілих інсайтів.</p>
				<p><small><span style="opacity:.8;">Esc</span> або клік поза вікном — закрити.</small></p>
			</div>
		</div>
	</div>
	<?php

	// Повідомлення (норіси)
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

	// === JS для модалки Info ===
	?>
	<script>
	// === INFO MODAL (API Keys page) ===
	(function($){
		var $modal    = $('#crit-keys-info-modal');
		var $dialog   = $modal.find('.crit-modal__dialog');
		var $openBtn  = $('#crit-keys-info-open');
		var $closeBtn = $('#crit-keys-info-close');
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
	echo '</div>'; // .wrap
}

/* ===========================================================
 * Secret reporter (Ctrl+Q) → modal → email на адміністратора сайту (get_option('admin_email'))
 * Працює лише в адмінці, лише для користувачів з manage_options,
 * показується тільки на сторінці "Critical Logger — API Keys".
 * =========================================================== */

// 1) AJAX-обробник відправлення
add_action('wp_ajax_crit_secret_send', function () {
	if ( ! current_user_can('manage_options')) {
		wp_send_json_error(['message' => 'Недостатньо прав'], 403);
	}

	check_ajax_referer('crit_secret_send', 'nonce');

	// Адресат — email адміністратора сайту (з налаштувань WordPress)
	$to = get_option('admin_email');

	$subject = isset($_POST['subject']) ? sanitize_text_field(wp_unslash($_POST['subject'])) : '';
	$message = isset($_POST['message']) ? wp_kses_post(wp_unslash($_POST['message'])) : '';

	if ($subject === '') {
		$subject = 'Повідомлення з адмінки: ' . wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
	}
	if (trim($message) === '') {
		wp_send_json_error(['message' => 'Поле повідомлення порожнє'], 400);
	}

	$current_user = wp_get_current_user();
	$meta = sprintf(
		"Сайт: %s\nЧас: %s\nКористувач: %s (%s)\n\n",
		site_url(),
		current_time('mysql'),
		$current_user ? $current_user->user_login : 'unknown',
		$current_user ? $current_user->user_email : 'unknown'
	);

	$admin_email = get_option('admin_email');
	$from_name   = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
	$headers     = [
		'Content-Type: text/plain; charset=UTF-8',
		'From: ' . $from_name . ' <' . $admin_email . '>',
		'Reply-To: ' . $from_name . ' <' . $admin_email . '>',
	];

	$ok = wp_mail($to, $subject, $meta . $message, $headers);

	if ($ok) {
		wp_send_json_success(['message' => 'Повідомлення надіслано']);
	} else {
		wp_send_json_error(['message' => 'Помилка відправки (wp_mail)'], 500);
	}
});

// 2) Рендер модалки + JS-хендлера на потрібній сторінці (footer адмінки)
add_action('admin_footer', function () {
	if ( ! current_user_can('manage_options')) return;
	$screen = function_exists('get_current_screen') ? get_current_screen() : null;
	// Показуємо лише на підсторінці critical-logger-keys
	if ( ! $screen || strpos($screen->id ?? '', 'critical-logger-keys') === false ) return;

	$nonce   = wp_create_nonce('crit_secret_send');
	$ajaxurl = admin_url('admin-ajax.php');
	?>
	<!-- ===== Secret reporter modal (Ctrl+Q) ===== -->
	<style>
		#crit-secret-overlay{
			display:none; position:fixed; inset:0; background:rgba(0,0,0,.35); z-index:100000;
		}
		#crit-secret-modal{
			display:none; position:fixed; z-index:100001; left:50%; top:50%;
			transform:translate(-50%,-50%); width:560px; max-width:92vw;
			background:#fff; border-radius:10px; box-shadow:0 10px 40px rgba(0,0,0,.25);
			font:14px/1.4 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
		}
		#crit-secret-modal header{
			padding:14px 16px; border-bottom:1px solid #e5e5e5; display:flex; align-items:center; justify-content:space-between;
		}
		#crit-secret-modal header h2{ margin:0; font-size:16px; }
		#crit-secret-modal .crit-close{ background:none; border:0; font-size:20px; cursor:pointer; line-height:1; }
		#crit-secret-modal .body{ padding:14px 16px; }
		#crit-secret-modal .body label{ display:block; margin:8px 0 6px; color:#333; }
		#crit-secret-modal input[type="text"],
		#crit-secret-modal textarea{
			width:100%; box-sizing:border-box; border:1px solid #c3c4c7; border-radius:6px; padding:8px;
		}
		#crit-secret-modal textarea{ min-height:150px; resize:vertical; }
		#crit-secret-modal .footer{
			padding:12px 16px; border-top:1px solid #e5e5e5; display:flex; gap:8px; justify-content:flex-end;
		}
		#crit-secret-modal .button-primary{ background:#2271b1; border-color:#2271b1; }
		#crit-secret-toast{
			position:fixed; right:18px; bottom:18px; background:#1d2327; color:#fff; padding:10px 14px; border-radius:8px;
			box-shadow:0 6px 24px rgba(0,0,0,.25); z-index:100002; display:none;
		}
	</style>

	<div id="crit-secret-overlay" aria-hidden="true"></div>
	<div id="crit-secret-modal" role="dialog" aria-modal="true" aria-labelledby="crit-secret-title">
		<header>
			<h2 id="crit-secret-title">📨 Приховане повідомлення</h2>
			<button type="button" class="crit-close" aria-label="Закрити">&times;</button>
		</header>
		<form id="crit-secret-form" class="body">
			<p style="margin:0 0 6px;color:#555">Ваше повідомлення буде відправлено на email адміністратора сайту (<?php echo esc_html(get_option('admin_email')); ?>)</p>
			<label for="crit-secret-subj">Тема (необов’язково)</label>
			<input type="text" id="crit-secret-subj" name="subject" placeholder="Тема">
			<label for="crit-secret-msg">Повідомлення</label>
			<textarea id="crit-secret-msg" name="message" placeholder="Опишіть проблему/подію" required></textarea>
			<div class="footer">
				<button type="button" class="button" id="crit-secret-cancel">Скасувати (Esc)</button>
				<button type="submit" class="button button-primary" id="crit-secret-send">Надіслати</button>
			</div>
		</form>
	</div>
	<div id="crit-secret-toast" role="status"></div>
<script>
(function(){
	const ajaxurl = <?php echo wp_json_encode($ajaxurl); ?>;
	const nonce   = <?php echo wp_json_encode($nonce); ?>;

	const overlay = document.getElementById('crit-secret-overlay');
	const modal   = document.getElementById('crit-secret-modal');
	const form    = document.getElementById('crit-secret-form');
	const cancel  = document.getElementById('crit-secret-cancel');
	const closeBt = modal.querySelector('.crit-close');
	const toast   = document.getElementById('crit-secret-toast');

	function isEditable(el){
		return el && (
			el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable ||
			(el.tagName === 'SELECT') || (el.closest && el.closest('.components-modal__frame'))
		);
	}

	function openModal(){
		overlay.style.display = 'block';
		modal.style.display   = 'block';
		setTimeout(() => document.getElementById('crit-secret-msg').focus(), 0);
	}
	function closeModal(){
		modal.style.display   = 'none';
		overlay.style.display = 'none';
	}
	function showToast(msg, ok){
		toast.textContent = msg;
		toast.style.background = ok ? '#198754' : '#d63638';
		toast.style.display = 'block';
		setTimeout(()=> toast.style.display='none', 4000);
	}

	overlay.addEventListener('click', closeModal);
	cancel.addEventListener('click', closeModal);
	closeBt.addEventListener('click', closeModal);
	document.addEventListener('keydown', function(e){
		if (e.key === 'Escape') closeModal();
	});

	/* --- Гаряча комбінація: ТІЛЬКИ Ctrl + Q --- */
	function isModifierOnly(e){
		return e.key === 'Control' || e.key === 'Shift' || e.key === 'Alt' || e.key === 'Meta'
			|| e.keyCode === 17 || e.keyCode === 16 || e.keyCode === 18 || e.keyCode === 91;
	}
	function onHotkey(e){
		if (isEditable(document.activeElement)) return;
		if (isModifierOnly(e)) return;

		const k = (e.key || '').toLowerCase();
		const isQ = (k === 'q') || (e.code === 'KeyQ') || (e.keyCode === 81);

		if (e.ctrlKey && isQ) {
			e.preventDefault();
			openModal();
		}
	}
	window.addEventListener('keydown', onHotkey, true);
	document.addEventListener('keydown', onHotkey, true);

	form.addEventListener('submit', function(e){
		e.preventDefault();
		const btn = document.getElementById('crit-secret-send');
		btn.disabled = true; btn.textContent = 'Надіслaю...';

		const fd = new FormData(form);
		fd.append('action', 'crit_secret_send');
		fd.append('nonce', nonce);

		fetch(ajaxurl, { method:'POST', credentials:'same-origin', body: fd })
			.then(resp => resp.json())
			.then(data => {
				if (data && data.success){
					showToast('Надіслано ✅', true);
					form.reset();
					closeModal();
				} else {
					showToast((data && data.data && data.data.message) ? data.data.message : 'Помилка відправки', false);
				}
			})
			.catch(() => showToast('Мережева помилка', false))
			.finally(() => { btn.disabled = false; btn.textContent = 'Надіслати'; });
	});
})();
</script>

	<?php
});