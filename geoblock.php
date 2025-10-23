<?php
/**
 * Critical Event Logger — helper module
 * GeoBlock (без deny/винятків шляхів/секретних байпасів)
 * Анти-фальшпозитив: консенсус джерел + відсутність cookie-кешу
 * Захист від самоблокування адміну
 * License: GPLv2 or later
 */

if (!defined('ABSPATH')) exit;

/* =========================
 * Опції за замовчуванням
 * ========================= */
function crit_geoblock_get_opt($key, $default = null) {
	$map = [
		'enabled'              => false,
		'reverse'              => false,                          // whitelist-режим для країн
		'countries'            => ['RU','CN','KP'],
		'trust_proxy'          => 'auto',                         // auto|yes|no
		'allow_ips'            => [],                             // масив IP/CIDR/діапазонів
		'response_mode'        => '403',                          // 403|404|451|redirect|custom
		'redirect_url'         => home_url('/'),
		'custom_html'          => '<h1>⛔ Доступ заборонено</h1><p>Вибачте, доступ із вашого регіону обмежено.</p>',
		'cache_ttl_hours'      => 12,
		'fail_open'            => true,                           // якщо GEO-API невпевнене/недоступне — пропускати
		'preview_only'         => false,                          // dry-run: лише лог
		'use_intel'            => false,                          // інтеграція з intel.php
		'intel_threshold'      => 80,                             // score для блокування
		'protect_own_country'  => true,                           // авто-захист від самоблокування країни адміну
		'cookie_ttl_hours'     => 12,                             // лишилось для сумісності (не використ. у консенсусі)
	];
	$opt = get_option('crit_geoblock_'.$key, null);
	return ($opt === null) ? ($map[$key] ?? $default) : $opt;
}

/* =========================
 * Хелпери: IP/CIDR/GEO
 * ========================= */

/** Реальний IP з урахуванням CDN/проксі */
function crit_geoblock_client_ip(): string {
	$trust = crit_geoblock_get_opt('trust_proxy', 'auto');

	// Cloudflare
	if (($trust === 'auto' || $trust === 'yes') && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
		$ip = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
		if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
	}
	// X-Forwarded-For — перший публічний
	if (($trust === 'yes') || ($trust === 'auto' && !empty($_SERVER['HTTP_X_FORWARDED_FOR']))) {
		$xff = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']) : [];
		foreach ($xff as $cand) {
			$ip = trim($cand);
			if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return $ip;
		}
	}
	// X-Real-IP
	if (($trust === 'auto' || $trust === 'yes') && !empty($_SERVER['HTTP_X_REAL_IP'])) {
		$ip = trim($_SERVER['HTTP_X_REAL_IP']);
		if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
	}
	// REMOTE_ADDR
	$ip = $_SERVER['REMOTE_ADDR'] ?? '';
	return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
}

/** Розбір списку IP/CIDR/діапазонів */
function crit_geoblock_parse_ip_list($raw): array {
	if (is_array($raw)) $s = $raw;
	else $s = preg_split('/[\s,]+/u', (string)$raw, -1, PREG_SPLIT_NO_EMPTY);
	$out = [];
	foreach ($s as $item) {
		$item = trim($item);
		if ($item === '') continue;
		if (strpos($item, '-') !== false) {
			[$a,$b] = array_map('trim', explode('-', $item, 2));
			foreach (crit_geoblock_range_to_cidrs($a, $b) as $c) $out[] = $c;
		} else {
			$out[] = $item;
		}
	}
	return array_values(array_unique($out));
}

/** Перевірка входження IP у CIDR (IPv4/IPv6) */
function crit_geoblock_ip_in_cidr($ip, $cidr): bool {
	if (strpos($cidr, '/') === false) return strcasecmp($ip, $cidr) === 0;
	[$sub, $mask] = explode('/', $cidr, 2);
	if (!filter_var($ip, FILTER_VALIDATE_IP) || !filter_var($sub, FILTER_VALIDATE_IP)) return false;
	$mask = (int)$mask; $is6 = strpos($ip, ':') !== false;
	if ($is6 !== (strpos($sub, ':') !== false)) return false;

	if ($is6) {
		$ipb = inet_pton($ip); $sb = inet_pton($sub);
		$bytes = intdiv($mask, 8); $bits = $mask % 8;
		if ($bytes && substr($ipb, 0, $bytes) !== substr($sb, 0, $bytes)) return false;
		if ($bits) {
			$maskByte = chr((0xFF00 >> $bits) & 0xFF);
			return (($ipb[$bytes] & $maskByte) === ($sb[$bytes] & $maskByte));
		}
		return true;
	}
	$ipl = ip2long($ip); $sbl = ip2long($sub);
	$ml = (~((1 << (32 - $mask)) - 1)) & 0xFFFFFFFF;
	return ($ipl & $ml) === ($sbl & $ml);
}

/** Діапазон IPv4 → мінімальний набір CIDR */
function crit_geoblock_range_to_cidrs($start, $end): array {
	if (!filter_var($start, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || !filter_var($end, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return [];
	$a = ip2long($start); $b = ip2long($end); if ($a === false || $b === false) return [];
	if ($a > $b) [$a,$b] = [$b,$a];
	$out = [];
	while ($a <= $b) {
		$maxSize = 32 - (int)floor(log(($a & -$a), 2));
		$maxDiff = 32 - (int)floor(log($b - $a + 1, 2));
		$size = max($maxSize, $maxDiff);
		$out[] = long2ip($a) . '/' . $size;
		$a += 1 << (32 - $size);
	}
	return $out;
}

/** Країни зі стореджу */
function crit_geoblock_get_countries() {
	$countries = crit_geoblock_get_opt('countries', ['RU','CN','KP']);
	return array_map('strtoupper', (array)$countries);
}

/**
 * Консенсус GEO: CF (якщо є) + ip-api + ipwho.is + ipapi.co
 * Повертає: ['code'=>'UA','confident'=>true/false,'sources'=>['cf'=>'UA','ipapi'=>'UA',...]]
 * Упевненість: 2+ збіги, або CF збігається з будь-яким іншим.
 * TTL: confident → 2 год; інакше → 10 хв. Без cookie.
 */
function crit_geoblock_country_consensus(string $ip): array {
	$res = ['code'=>'??','confident'=>false,'sources'=>[]];
	if (!filter_var($ip, FILTER_VALIDATE_IP)) return $res;

	$ckey = 'crit_geo_consensus_' . md5($ip);
	$cached = get_transient($ckey);
	if ($cached !== false && is_array($cached)) return $cached;

	$sources = [];

	// Cloudflare country
	if (!empty($_SERVER['HTTP_CF_IPCOUNTRY'])) {
		$cf = strtoupper(trim($_SERVER['HTTP_CF_IPCOUNTRY']));
		if (preg_match('/^[A-Z]{2}$/', $cf)) $sources['cf'] = $cf;
	}

	// ip-api (HTTP)
	$r1 = wp_remote_get("http://ip-api.com/json/{$ip}?fields=status,countryCode", ['timeout'=>6]);
	if (!is_wp_error($r1)) {
		$d1 = json_decode(wp_remote_retrieve_body($r1), true);
		if (($d1['status'] ?? '') === 'success' && !empty($d1['countryCode'])) {
			$sources['ipapi'] = strtoupper($d1['countryCode']);
		}
	}

	// ipwho.is
	$r2 = wp_remote_get("https://ipwho.is/{$ip}", ['timeout'=>6]);
	if (!is_wp_error($r2)) {
		$d2 = json_decode(wp_remote_retrieve_body($r2), true);
		if (!empty($d2['success']) && !empty($d2['country_code'])) {
			$sources['ipwho'] = strtoupper($d2['country_code']);
		}
	}

	// ipapi.co
	$r3 = wp_remote_get("https://ipapi.co/{$ip}/country/", ['timeout'=>6]);
	if (!is_wp_error($r3)) {
		$raw = strtoupper(trim(wp_remote_retrieve_body($r3)));
		if (preg_match('/^[A-Z]{2}$/', $raw)) $sources['ipapi_co'] = $raw;
	}

	// Підрахунок голосів
	$votes = [];
	foreach ($sources as $cc) { $votes[$cc] = ($votes[$cc] ?? 0) + 1; }

	$code = '??';
	$conf = false;

	if ($votes) {
		arsort($votes);
		$top = array_key_first($votes);
		$cnt = $votes[$top];

		if ($cnt >= 2) {
			$code = $top; $conf = true;
		} else {
			if (isset($sources['cf'])) {
				foreach ($sources as $name => $cc) {
					if ($name !== 'cf' && $cc === $sources['cf']) {
						$code = $cc; $conf = true; break;
					}
				}
			}
			if (!$conf && !empty($sources['ipapi'])) {
				$code = $sources['ipapi'];
			}
		}
	}

	$res['code']      = $code;
	$res['confident'] = $conf;
	$res['sources']   = $sources;

	$ttl = $conf ? 2 * HOUR_IN_SECONDS : 10 * MINUTE_IN_SECONDS;
	set_transient($ckey, $res, $ttl);

	return $res;
}

/** Геттер коду країни з консенсусу (якщо НЕ впевнено — '??' для fail-open) */
function crit_geoblock_get_country($ip) {
	$cons = crit_geoblock_country_consensus($ip);
	return !empty($cons['confident']) ? ($cons['code'] ?? '??') : '??';
}

/* =========================
 * Рішення: блокувати чи ні
 * ========================= */
function crit_geoblock_should_block($ip, $country): array {
	$reverse = (bool) crit_geoblock_get_opt('reverse', false);
	$list    = crit_geoblock_get_countries();
	$failOpen= (bool) crit_geoblock_get_opt('fail_open', true);

	// 1) Allow-IP/CIDR завжди дозволені
	$allow = crit_geoblock_parse_ip_list(crit_geoblock_get_opt('allow_ips', []));
	foreach ($allow as $cidr) if (crit_geoblock_ip_in_cidr($ip, $cidr)) return ['block'=>false, 'reason'=>'allowlist-ip'];

	// 2) Інтел-перевірка (якщо ввімкнено)
	if (crit_geoblock_get_opt('use_intel', false) && function_exists('crit_get_ip_score')) {
		$score = (int) (crit_get_ip_score($ip)['score'] ?? 0);
		$thr   = (int) crit_geoblock_get_opt('intel_threshold', 80);
		if ($score >= $thr) return ['block'=>true, 'reason'=>"intel-score-$score"];
	}

	// 3) GEO
	if ($country === '??') {
		return ['block'=> !$failOpen, 'reason'=> $failOpen ? 'geo-fail-open' : 'geo-fail-closed'];
	}
	if ($reverse) {
		return ['block'=> !in_array($country, $list, true), 'reason'=> in_array($country,$list,true) ? 'geo-allow' : 'geo-not-in-allow'];
	}
	return ['block'=> in_array($country, $list, true), 'reason'=> in_array($country,$list,true) ? 'geo-deny' : 'geo-allow'];
}

/* =========================
 * Відповідь користувачу
 * ========================= */
function crit_geoblock_send_response($mode, $ip, $country) {
	nocache_headers();
	switch ($mode) {
		case '404':
			status_header(404);
			wp_die('<h1>404 Not Found</h1>', 'Not Found', ['response'=>404]);
		case '451':
			status_header(451);
			wp_die('<h1>451 Unavailable For Legal Reasons</h1>', 'Unavailable For Legal Reasons', ['response'=>451]);
		case 'redirect':
			wp_redirect(esc_url_raw((string) crit_geoblock_get_opt('redirect_url', home_url('/'))), 302);
			exit;
		case 'custom':
			status_header(403);
			$html = (string) crit_geoblock_get_opt('custom_html', '<h1>⛔ Доступ заборонено</h1>');
			if (stripos($html, '<html') === false) {
				wp_die($html . '<p style="color:#666;font-size:12px">('.esc_html($ip).' / '.esc_html($country).')</p>', 'GeoBlock', ['response'=>403]);
			}
			echo $html; exit;
		case '403':
		default:
			status_header(403);
			wp_die('<h1>⛔ Доступ заборонено</h1><p>Ваш IP (' . esc_html($ip) . ') з країни ' . esc_html($country) . ' не має доступу до сайту.</p>', 'GeoBlock', ['response'=>403]);
	}
}

/* =========================
 * Основна логіка (front only)
 * ========================= */
add_action('init', function(){
	if (is_admin()) return;
	if (defined('DOING_AJAX') && DOING_AJAX) return;
	if (defined('DOING_CRON') && DOING_CRON) return;
	if (wp_doing_cron()) return;
	if (current_user_can('manage_options')) return;
	if (!crit_geoblock_get_opt('enabled', false)) return;

	$ip = crit_geoblock_client_ip();
	if ($ip === '') return;

	$cons    = crit_geoblock_country_consensus($ip);
	$country = !empty($cons['confident']) ? ($cons['code'] ?? '??') : '??';

	$verdict = crit_geoblock_should_block($ip, $country);
	$preview = (bool) crit_geoblock_get_opt('preview_only', false);

	if (!empty($verdict['block'])) {
		// --- коротке логування + маркер бота ---
		$log_file = crit_log_file();
		$ua_raw   = $_SERVER['HTTP_USER_AGENT'] ?? '';
		$bot_tag  = '';
		if (stripos($ua_raw, 'bingbot/2.0') !== false) {
			$bot_tag = ' (bingbot)';
		} elseif (stripos($ua_raw, 'SemrushBot/7~bl') !== false) {
			$bot_tag = ' (SemrushBot)';
		}

		if ($preview) {
			$entry = '[' . crit_log_time() . "][GeoBlock][$country][INFO] ПРЕВʼЮ: Заблоковано вхід з країни $country ($ip)$bot_tag\n";
			@file_put_contents($log_file, $entry, FILE_APPEND | LOCK_EX);
			return;
		}

		$entry = '[' . crit_log_time() . "][GeoBlock][$country][WARN] Заблоковано вхід з країни $country ($ip)$bot_tag\n";
		@file_put_contents($log_file, $entry, FILE_APPEND | LOCK_EX);

		crit_geoblock_send_response((string) crit_geoblock_get_opt('response_mode','403'), $ip, $country);
	} else {
		// Раніше тут писався INFO про fail-open з масою полів — прибрано, щоб лог не роздувався.
		return;
	}
}, 0);

/* =========================
 * Адмінка (охайний інтерфейс)
 * ========================= */
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
	// Діагностика перед збереженням
	$diag_ip = crit_geoblock_client_ip();
	$cons    = $diag_ip ? crit_geoblock_country_consensus($diag_ip) : ['code'=>'—','confident'=>false,'sources'=>[]];
	$myCC    = !empty($cons['confident']) ? ($cons['code'] ?? '') : '';

	if (isset($_POST['crit_geoblock_save'])) {
		check_admin_referer('crit_geoblock_save_action', 'crit_geoblock_nonce');

		$enabled = !empty($_POST['crit_geoblock_enabled']);
		$reverse = !empty($_POST['crit_geoblock_reverse']);
		$trust   = sanitize_text_field($_POST['crit_geoblock_trust_proxy'] ?? 'auto');
		$countries = array_filter(array_map('trim', explode(',', strtoupper(trim($_POST['crit_geoblock_countries'] ?? '')))));
		$allow_ips = crit_geoblock_parse_ip_list($_POST['crit_geoblock_allow_ips'] ?? '');
		$respMode  = sanitize_text_field($_POST['crit_geoblock_response_mode'] ?? '403');
		$redirUrl  = esc_url_raw($_POST['crit_geoblock_redirect_url'] ?? home_url('/'));
		$cHtml     = wp_kses_post($_POST['crit_geoblock_custom_html'] ?? '');
		$ttl       = (int)($_POST['crit_geoblock_cache_ttl_hours'] ?? 12);
		$failOpen  = !empty($_POST['crit_geoblock_fail_open']);
		$preview   = !empty($_POST['crit_geoblock_preview_only']);
		$useIntel  = !empty($_POST['crit_geoblock_use_intel']);
		$intelThr  = (int)($_POST['crit_geoblock_intel_threshold'] ?? 80);
		$protect   = !empty($_POST['crit_geoblock_protect_own_country']);

		// Захист від самоблокування: якщо blacklist і моя країна у списку — вилучити її
		$removedSelf = false;
		if ($protect && !$reverse && $myCC && in_array($myCC, $countries, true)) {
			$countries = array_values(array_diff($countries, [$myCC]));
			$removedSelf = true;
		}

		update_option('crit_geoblock_enabled',             $enabled);
		update_option('crit_geoblock_reverse',             $reverse);
		update_option('crit_geoblock_trust_proxy',         $trust);
		update_option('crit_geoblock_countries',           $countries);
		update_option('crit_geoblock_allow_ips',           $allow_ips);
		update_option('crit_geoblock_response_mode',       $respMode);
		update_option('crit_geoblock_redirect_url',        $redirUrl);
		update_option('crit_geoblock_custom_html',         $cHtml);
		update_option('crit_geoblock_cache_ttl_hours',     max(1, $ttl));
		update_option('crit_geoblock_fail_open',           $failOpen);
		update_option('crit_geoblock_preview_only',        $preview);
		update_option('crit_geoblock_use_intel',           $useIntel);
		update_option('crit_geoblock_intel_threshold',     $intelThr);
		update_option('crit_geoblock_protect_own_country', $protect);

		echo '<div class="notice notice-success"><p>✅ Налаштування GeoBlock збережено.</p></div>';
		if ($removedSelf) {
			echo '<div class="notice notice-warning"><p>ℹ️ Захист від самоблокування вилучив <strong>'.esc_html($myCC).'</strong> зі списку заблокованих країн.</p></div>';
		}

		// оновимо діагностику після збереження
		$cons = $diag_ip ? crit_geoblock_country_consensus($diag_ip) : ['code'=>'—','confident'=>false,'sources'=>[]];
		$myCC = !empty($cons['confident']) ? ($cons['code'] ?? '') : '';
	}

	$enabled     = crit_geoblock_get_opt('enabled');
	$reverse     = crit_geoblock_get_opt('reverse');
	$trust       = crit_geoblock_get_opt('trust_proxy');
	$countriesStr= implode(', ', crit_geoblock_get_opt('countries'));
	$allowIps    = implode("\n", (array)crit_geoblock_get_opt('allow_ips'));
	$respMode    = (string)crit_geoblock_get_opt('response_mode','403');
	$redirUrl    = (string)crit_geoblock_get_opt('redirect_url', home_url('/'));
	$cHtml       = (string)crit_geoblock_get_opt('custom_html','');
	$ttl         = (int)crit_geoblock_get_opt('cache_ttl_hours',12);
	$failOpen    = (bool)crit_geoblock_get_opt('fail_open',true);
	$preview     = (bool)crit_geoblock_get_opt('preview_only',false);
	$useIntel    = (bool)crit_geoblock_get_opt('use_intel',false);
	$intelThr    = (int)crit_geoblock_get_opt('intel_threshold',80);
	$protect     = (bool)crit_geoblock_get_opt('protect_own_country',true);

	// Підсумковий вердикт (за поточними опціями)
	$diag_v  = $diag_ip ? crit_geoblock_should_block($diag_ip, (!empty($cons['confident']) ? ($cons['code'] ?? '??') : '??')) : ['block'=>false,'reason'=>'no-ip'];
	$src_str = $cons['sources'] ? implode(', ', array_map(function($k,$v){ return "$k=$v"; }, array_keys($cons['sources']), $cons['sources'])) : '-';

	echo '<div class="wrap crit-geo-wrap" data-mycc="'.esc_attr($myCC).'">';

	// === СТИЛІ інтерфейсу ===
	echo '<style>
		.crit-geo-wrap{ --c-border:#e5e7eb; --c-muted:#64748b; --c-bg:#fff; --c-pill:#eef2ff; --c-ok:#059669; --c-bad:#b91c1c; --c-warn:#b45309; }
		.crit-head{display:flex;gap:12px;justify-content:space-between;align-items:center;margin-bottom:12px}
		.crit-head h1{margin:0}
		.crit-chips{display:flex;gap:8px;flex-wrap:wrap}
		.chip{padding:4px 8px;border:1px solid var(--c-border);border-radius:999px;background:#fafafa;font-size:12px;color:#111}
		.chip.ok{border-color:#bbf7d0;background:#f0fdf4}
		.chip.bad{border-color:#fecaca;background:#fef2f2}
		.chip.warn{border-color:#fde68a;background:#fffbeb}

		.crit-grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:12px}
		.col-7{grid-column:span 7}
		.col-5{grid-column:span 5}
		@media(max-width:1100px){ .col-7,.col-5{grid-column:span 12} }

		.card{background:var(--c-bg);border:1px solid var(--c-border);border-radius:10px;padding:12px}
		.card h2{margin:0 0 8px;font-size:16px}
		.desc{color:var(--c-muted);font-size:12px;margin:-2px 0 8px}
		.row{margin:10px 0}
		.row label{display:block;margin-bottom:6px}
		input[type="text"],input[type="url"],textarea,select{width:100%;max-width:100%}
		textarea{min-height:90px}
		.sticky-save{position:sticky;bottom:0;z-index:10;background:#fff;border:1px solid var(--c-border);border-radius:10px;padding:10px;display:flex;justify-content:space-between;align-items:center;margin-top:12px}
		.sticky-save .note{font-size:12px;color:var(--c-muted)}
		.kbd{display:inline-block;border:1px solid #ddd;border-bottom-width:2px;border-radius:4px;padding:0 5px;font:12px/20px monospace;background:#f8f8f8}

		.notice-inline{margin-top:8px}
	</style>';

	// === ШАПКА з чіпами стану ===
	echo '<div class="crit-head">';
		echo '<h1>🌍 GeoBlock — Географічне блокування</h1>';
		echo '<div class="crit-chips">';
			echo '<span class="chip '.($enabled?'ok':'warn').'">'.($enabled?'Увімкнено':'Вимкнено').'</span>';
			echo '<span class="chip">'.($reverse?'Whitelist':'Blacklist').'</span>';
			$confChip = !empty($cons['confident']) ? '<span class="chip ok">Geo: впевнено</span>' : '<span class="chip warn">Geo: невпевнено</span>';
			echo $confChip;
			$verChip = !empty($diag_v['block'])
				? '<span class="chip bad">Вердикт: BLOCK</span>'
				: '<span class="chip ok">Вердикт: ALLOW</span>';
			echo $verChip;
		echo '</div>';

	// Кнопка відкриття модалки
      echo '<button type="button" id="crit-geo-info-open" class="button button-secondary" aria-haspopup="dialog" aria-expanded="false" aria-controls="crit-geo-info-modal">Info</button>';
    echo '</div>';
	// === ПОПЕРЕДЖЕННЯ про самоблок (якщо доречно) ===
	if (!$reverse && $myCC && in_array($myCC, array_map('trim', explode(',', strtoupper($countriesStr))), true)) {
		echo '<div class="notice notice-error notice-inline"><p>⚠️ У чорному списку є ваша країна <strong>'.esc_html($myCC).'</strong>. '
		   . 'Увімкнено «Захист від самоблокування» — при збереженні країну буде вилучено автоматично.</p></div>';
	}

	// === ФОРМА ===
	echo '<form method="post" id="crit-geo-form">';
	wp_nonce_field('crit_geoblock_save_action', 'crit_geoblock_nonce');

	echo '<div class="crit-grid">';

	// Ліва колонка (7)
	echo '<div class="col-7">';

		// Загальні
		echo '<div class="card">';
		echo '<h2>Загальні налаштування</h2><div class="desc">Базові параметри роботи GeoBlock.</div>';
		echo '<div class="row"><label><input type="checkbox" name="crit_geoblock_enabled" value="1" '.checked($enabled,true,false).'> <strong>Увімкнути GeoBlock</strong></label></div>';
		echo '<div class="row"><label><input type="checkbox" name="crit_geoblock_reverse" value="1" '.checked($reverse,true,false).'> Режим “дозволені країни” (інші блокуються)</label></div>';
		echo '<div class="row"><label>Довіра до проксі (для реального IP):</label>
			<select name="crit_geoblock_trust_proxy">
				<option value="auto" '.selected($trust,'auto',false).'>Auto</option>
				<option value="yes"  '.selected($trust,'yes',false).'>Так (довіряю X-Forwarded-For)</option>
				<option value="no"   '.selected($trust,'no',false).'>Ні</option>
			</select></div>';
		echo '</div>';

		// Країни
		echo '<div class="card">';
		echo '<h2>Країни</h2><div class="desc">ISO-коди через кому (напр. <code>UA, PL, US</code>)</div>';
		echo '<div class="row"><label for="crit_geo_countries">Коди країн (ISO-2):</label>
			<input id="crit_geo_countries" type="text" name="crit_geoblock_countries" value="'.esc_attr($countriesStr).'" placeholder="UA, PL, US"></div>';
		echo '<div class="row"><small class="desc" id="crit_geo_self_hint" style="display:none;">⚠️ У списку виявлено вашу країну — це призведе до блокування (у blacklist). Збереження автоматично її прибере, якщо увімкнено захист.</small></div>';
		echo '</div>';

		// Allow IP
		echo '<div class="card">';
		echo '<h2>Allow IP (опційно)</h2><div class="desc">IP / CIDR або діапазони <code>start-end</code>, кожен у новому рядку.</div>';
		echo '<div class="row"><textarea name="crit_geoblock_allow_ips" rows="5" placeholder="203.0.113.10&#10;203.0.113.0/24&#10;203.0.113.10-203.0.113.20">'.esc_textarea($allowIps).'</textarea></div>';
		echo '</div>';

	echo '</div>';

	// Права колонка (5)
	echo '<div class="col-5">';

		// Режим відповіді
		echo '<div class="card">';
		echo '<h2>Режим відповіді</h2><div class="desc">Що побачить заблокований користувач.</div>';
		echo '<div class="row"><label>Тип відповіді:</label>
			<select name="crit_geoblock_response_mode">
				<option value="403" '.selected($respMode,'403',false).'>403 Forbidden</option>
				<option value="404" '.selected($respMode,'404',false).'>404 Not Found</option>
				<option value="451" '.selected($respMode,'451',false).'>451 Legal Reasons</option>
				<option value="redirect" '.selected($respMode,'redirect',false).'>Redirect</option>
				<option value="custom" '.selected($respMode,'custom',false).'>Custom HTML</option>
			</select></div>';
		echo '<div class="row"><label>Redirect URL:</label>
			<input type="url" name="crit_geoblock_redirect_url" value="'.esc_attr($redirUrl).'" placeholder="'.esc_attr(home_url('/')).'"></div>';
		echo '<div class="row"><label>Custom HTML:</label>
			<textarea name="crit_geoblock_custom_html" rows="4" placeholder="<h1>⛔ Доступ заборонено</h1>">'.esc_textarea($cHtml).'</textarea></div>';
		echo '</div>';

		// Кеш/надійність
		echo '<div class="card">';
		echo '<h2>Кеш і надійність</h2><div class="desc">Fail-open пропускає трафік при невпевненості GEO.</div>';
		echo '<div class="row"><label>Geo-cache TTL (год):</label>
			<input type="number" name="crit_geoblock_cache_ttl_hours" min="1" value="'.(int)$ttl.'" style="width:120px"></div>';
		echo '<div class="row"><label><input type="checkbox" name="crit_geoblock_fail_open" value="1" '.checked($failOpen,true,false).'> Якщо GEO-API невпевнене/недоступне — пропускати (Fail-Open)</label></div>';
		echo '<div class="row"><label><input type="checkbox" name="crit_geoblock_preview_only" value="1" '.checked($preview,true,false).'> Превʼю (тільки логувати, без блокування)</label></div>';
		echo '</div>';

		// Інтел
		echo '<div class="card">';
		echo '<h2>Інтел (опційно)</h2><div class="desc">Додаткове правило блокування за <em>intel-score</em> (див. модуль інтел-аналізу).</div>';
		echo '<div class="row"><label><input type="checkbox" name="crit_geoblock_use_intel" value="1" '.checked($useIntel,true,false).'> Використовувати intel-score</label></div>';
		echo '<div class="row"><label>Поріг score:</label> <input type="number" name="crit_geoblock_intel_threshold" value="'.(int)$intelThr.'" min="0" max="150" style="width:120px"></div>';
		echo '</div>';

		// Захист
		echo '<div class="card">';
		echo '<h2>Захист</h2><div class="desc">Анти-самоблокування для адміністратора.</div>';
		echo '<div class="row"><label><input type="checkbox" name="crit_geoblock_protect_own_country" value="1" '.checked($protect,true,false).'> Автоматично вилучати мою країну з blacklist під час збереження</label></div>';
		echo '</div>';

		// Діагностика
		$ccLabel = esc_html($cons['code']);
		$confLbl = !empty($cons['confident']) ? '<span class="chip ok">впевнено</span>' : '<span class="chip warn">невпевнено</span>';
		$verChip = !empty($diag_v['block']) ? '<span class="chip bad">BLOCK</span>' : '<span class="chip ok">ALLOW</span>';
		echo '<div class="card">';
		echo '<h2>Діагностика</h2><div class="desc">Поточне визначення для вашого підключення.</div>';
		echo '<div class="row">IP: <code>'.esc_html($diag_ip ?: '—').'</code></div>';
		echo '<div class="row">Country (consensus): <code>'.$ccLabel.'</code> '.$confLbl.'</div>';
		echo '<div class="row">Sources: <code>'.esc_html($src_str).'</code></div>';
		echo '<div class="row">Вердикт: '.$verChip.' <small class="desc">('.esc_html($diag_v['reason'] ?? '').')</small></div>';
		echo '</div>';

	echo '</div>'; // правий стовпчик

	echo '</div>'; // grid

	// Липка панель Зберегти
	echo '<div class="sticky-save">';
	echo '<div><input type="submit" name="crit_geoblock_save" class="button button-primary" value="💾 Зберегти"></div>';
	echo '</div>';

	echo '</form>';
	// === INFO MODAL: довідка по GeoBlock ===
echo '<style id="crit-geo-info-css">
#crit-geo-info-modal[hidden]{display:none;}
#crit-geo-info-modal{position:fixed;inset:0;z-index:100000;}
#crit-geo-info-modal .crit-modal__backdrop{position:absolute;inset:0;background:rgba(0,0,0,.35);}
#crit-geo-info-modal .crit-modal__dialog{
  position:relative;max-width:880px;margin:6vh auto;background:#fff;border-radius:10px;
  box-shadow:0 10px 30px rgba(0,0,0,.25);padding:18px 20px;outline:0;border:1px solid #e5e7eb;
}
#crit-geo-info-modal h2{margin:0 40px 6px 0;font-size:20px}
#crit-geo-info-modal .crit-modal__body{line-height:1.55;max-height:70vh;overflow:auto;padding-right:4px}
#crit-geo-info-modal .crit-modal__body h3{margin:14px 0 6px;font-size:15px}
#crit-geo-info-modal .crit-modal__body ul{margin:6px 0 10px 20px}
#crit-geo-info-modal .crit-modal__body li{margin:4px 0}
#crit-geo-info-modal .crit-modal__body code{background:#f6f7f7;border:1px solid #e2e4e7;border-radius:3px;padding:1px 4px}
#crit-geo-info-modal .crit-modal__close{
  position:absolute;right:12px;top:10px;border:0;background:transparent;font-size:22px;line-height:1;cursor:pointer;
}
#crit-geo-info-modal .crit-kbd{display:inline-block;border:1px solid #ddd;border-bottom-width:2px;border-radius:4px;padding:0 5px;font:12px/20px monospace;background:#f8f8f8}
#crit-geo-info-modal .crit-note{color:#64748b;font-size:12px}
</style>';

echo '<div id="crit-geo-info-modal" role="dialog" aria-modal="true" aria-labelledby="crit-geo-info-title" hidden>
  <div class="crit-modal__backdrop" data-close="1"></div>
  <div class="crit-modal__dialog" role="document" tabindex="-1">
    <button type="button" class="crit-modal__close" id="crit-geo-info-close" aria-label="Закрити" title="Закрити (Esc)">×</button>
    <h2 id="crit-geo-info-title">Довідка: GeoBlock</h2>
    <div class="crit-modal__body">
      <h3>Що робить GeoBlock</h3>
      <ul>
        <li>Обмежує доступ до сайту за країною відвідувача (frontend). Адміністратори, <code>wp-admin</code>, AJAX/CRON — не блокуються.</li>
        <li>Має два режими: <em>Blacklist</em> (блокуємо перелік країн) та <em>Whitelist</em> (дозволяємо лише перелік країн).</li>
      </ul>

      <h3>Як визначається країна (консенсус)</h3>
      <ul>
        <li>Джерела: <code>HTTP_CF_IPCOUNTRY</code> (якщо сайт за Cloudflare), <code>ip-api.com</code>, <code>ipwho.is</code>, <code>ipapi.co</code>.</li>
        <li><strong>Впевненість</strong>: коли співпало ≥2 джерела або <code>Cloudflare</code> збігся з будь-яким іншим.</li>
        <li>Коли невпевнено або країна <code>??</code> — спрацьовує <em>Fail-Open</em> (пропускаємо), якщо опція увімкнена.</li>
        <li>Кеш GEO: впевнено — ~2 год; невпевнено — ~10 хв.</li>
      </ul>

      <h3>Опції</h3>
      <ul>
        <li><strong>Увімкнути GeoBlock</strong> — вмикає перевірку для фронтенду.</li>
        <li><strong>Режим “дозволені країни”</strong> — <em>Whitelist</em>; без нього — <em>Blacklist</em>.</li>
        <li><strong>Коди країн</strong> — ISO-2 через кому (напр. <code>UA, PL, US</code>).</li>
        <li><strong>Allow IP</strong> — список IP / CIDR або діапазони <code>start-end</code>, які <em>завжди</em> дозволені.</li>
        <li><strong>Довіра до проксі</strong> — <code>auto | yes | no</code>. Дозволяє брати реальний IP з <code>CF-Connecting-IP</code>, <code>X-Forwarded-For</code>, <code>X-Real-IP</code>.</li>
        <li><strong>Режим відповіді</strong> — <code>403</code>, <code>404</code>, <code>451</code>, <code>redirect</code> або <code>custom</code>.</li>
        <li><strong>Redirect URL</strong> — куди перенаправляти у режимі <em>redirect</em>.</li>
        <li><strong>Custom HTML</strong> — власне повідомлення при блокуванні у режимі <em>custom</em>.</li>
        <li><strong>Geo-cache TTL</strong> — тривалість кешування відповіді GEO.</li>
        <li><strong>Fail-Open</strong> — якщо GEO-сервіси недоступні/невпевнені, трафік пропускається.</li>
        <li><strong>Превʼю</strong> — “сухий запуск”: лише логування без реального блокування.</li>
        <li><strong>Інтел (опційно)</strong> — якщо підключено <code>intel.php</code>, блокує при <em>score</em> ≥ порогу.</li>
        <li><strong>Захист від самоблокування</strong> — під час збереження з <em>Blacklist</em> автоматично прибирає вашу країну зі списку.</li>
      </ul>

      <h3>Логування</h3>
      <ul>
        <li>Короткий формат: <code>Заблоковано вхід з країни CC (IP)</code>.</li>
        <li>Якщо User-Agent містить <code>bingbot/2.0</code> або <code>SemrushBot/7~bl</code> — додається мітка <code>(bingbot)</code> / <code>(SemrushBot)</code>.</li>
        <li>У режимі “Превʼю” рівень <code>INFO</code> з префіксом <code>ПРЕВʼЮ:</code>. Дозволи/Fail-Open у лог не пишуться.</li>
      </ul>

      <h3>Інфраструктура й безпека</h3>
      <ul>
        <li>Працює з реальним IP клієнта (Cloudflare/проксі враховуються згідно з “Довіра до проксі”).</li>
        <li>Плагін <em>не</em> змінює <code>.htaccess</code>. У випадку проблем — просто вимкніть модуль.</li>
      </ul>

      <h3>Поради</h3>
      <ul>
        <li>Перевірку власного доступу дивись у блоці “Діагностика”.</li>
        <li>Швидке збереження: <span class="crit-kbd">Ctrl</span> + <span class="crit-kbd">S</span>.</li>
      </ul>
    </div>
  </div>
</div>

<script>
(function(){
  var modal  = document.getElementById("crit-geo-info-modal");
  var openBn = document.getElementById("crit-geo-info-open");
  var closeBn= document.getElementById("crit-geo-info-close");
  var dialog = modal ? modal.querySelector(".crit-modal__dialog") : null;
  var lastFocus = null;

  function openModal(){
    if(!modal) return;
    lastFocus = document.activeElement;
    modal.removeAttribute("hidden");
    if(openBn) openBn.setAttribute("aria-expanded","true");
    setTimeout(function(){ if(dialog){ dialog.focus(); } }, 0);
  }
  function closeModal(){
    if(!modal) return;
    modal.setAttribute("hidden","hidden");
    if(openBn) openBn.setAttribute("aria-expanded","false");
    if(lastFocus && typeof lastFocus.focus === "function"){ lastFocus.focus(); }
  }

  if(openBn) openBn.addEventListener("click", function(e){ e.preventDefault(); openModal(); });
  if(closeBn) closeBn.addEventListener("click", closeModal);
  if(modal){
    modal.addEventListener("click", function(e){
      if(e.target && (e.target.getAttribute("data-close") || e.target.classList.contains("crit-modal__backdrop"))){
        closeModal();
      }
    });
  }
  document.addEventListener("keydown", function(e){
    if(e.key === "Escape" && modal && !modal.hasAttribute("hidden")){
      e.preventDefault(); closeModal();
    }
  });
})();
</script>';

	// Невеличкий JS: підсвічування ризику самоблоку (лайв)
	echo '<script>
	(function(){
	  var input = document.getElementById("crit_geo_countries");
	  var hint  = document.getElementById("crit_geo_self_hint");
	  var wrap  = document.querySelector(".crit-geo-wrap");
	  if(!input || !wrap) return;
	  var myCC  = (wrap.getAttribute("data-mycc")||"").toUpperCase();

	  function checkSelf(){
	    if(!myCC){ if(hint) hint.style.display="none"; return; }
	    var t = (input.value||"").toUpperCase().split(",").map(function(s){return s.trim();}).filter(Boolean);
	    var reverse = document.querySelector("input[name=crit_geoblock_reverse]")?.checked;
	    var has = t.indexOf(myCC) !== -1;
	    // попереджаємо лише у blacklist-режимі
	    if(hint) hint.style.display = (!reverse && has) ? "block" : "none";
	  }
	  input.addEventListener("input", checkSelf);
	  var rev = document.querySelector("input[name=crit_geoblock_reverse]");
	  if(rev) rev.addEventListener("change", checkSelf);
	  checkSelf();

	  // Ctrl+S → submit
	  document.addEventListener("keydown", function(e){
	    if(e.key === "s" && (e.ctrlKey || e.metaKey)){
	      e.preventDefault();
	      var btn = document.querySelector("input[name=crit_geoblock_save]");
	      if(btn){ btn.click(); }
	    }
	  });
	})();
	</script>';

	echo '</div>'; // wrap
}