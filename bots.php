<?php
/**
 * Critical Event Logger — Bots allowlist (many useful bots)
 * Дозволяє обраним пошуковим/корисним ботам обійти GeoBlock і IP-блоки у .htaccess.
 * Примітка: у .htaccess винятки можливі лише за User-Agent (UA можна підробити);
 * у PHP для GeoBlock робимо перевірку справжності через reverse+forward DNS (де можливо).
 */
if (!defined('ABSPATH')) exit;

if (!defined('CRIT_BOT_TTL')) define('CRIT_BOT_TTL', DAY_IN_SECONDS);

/** Скільки бекапів .htaccess тримати */
if (!defined('CRIT_BOT_BAK_KEEP')) define('CRIT_BOT_BAK_KEEP', 3);

/** Прибрати старі .htaccess.bak-* і лишити $keep новіших */
function crit_prune_htaccess_backups(string $htaccess_path, ?int $keep = null): void {
	$keep = $keep ?? (int) apply_filters('crit_bot_bak_keep', defined('CRIT_BOT_BAK_KEEP') ? CRIT_BOT_BAK_KEEP : 3);
	$keep = max(0, (int)$keep);

	$dir  = dirname($htaccess_path);
	$base = basename($htaccess_path); // ".htaccess"
	$glob = $dir . DIRECTORY_SEPARATOR . $base . '.bak-*';

	$files = glob($glob);
	if (!$files || !is_array($files)) return;

	// Сортуємо за mtime (новіші спочатку)
	usort($files, static function($a, $b) {
		$ma = @filemtime($a) ?: 0;
		$mb = @filemtime($b) ?: 0;
		return $mb <=> $ma;
	});

	// Видаляємо все, що після перших $keep
	if (count($files) > $keep) {
		foreach (array_slice($files, $keep) as $old) {
			@unlink($old);
		}
	}
}


/** Реєстр ботів: ключ => [label, ua, verify, rdns[]]
 * verify: 'rdns' (строгий: rDNS+forward) або 'ua' (лише UA; менш безпечно).
 * Можна розширювати через фільтр 'crit_bots_registry'.
 */
function crit_bots_registry(): array {
	$bots = [
		// Основні пошукові (строга перевірка)
		'google' => [
			'label'  => 'Googlebot',
			'ua'     => 'googlebot|adsbot-google|apis-google|mediapartners-google|feedfetcher-google|duplexweb-google',
			'verify' => 'rdns',
			'rdns'   => ['.googlebot.com', '.google.com'],
		],
		'bing' => [
			'label'  => 'Bingbot',
			'ua'     => 'bingbot|adidxbot|msnbot',
			'verify' => 'rdns',
			'rdns'   => ['.search.msn.com', '.bing.com'],
		],
		'duckduck' => [
			'label'  => 'DuckDuckBot',
			'ua'     => 'duckduckbot|duckduckgo',
			'verify' => 'rdns',
			'rdns'   => ['.duckduckgo.com'],
		],
		'apple' => [
			'label'  => 'Applebot',
			'ua'     => 'applebot',
			'verify' => 'rdns',
			'rdns'   => ['.apple.com'],
		],
		'baidu' => [
			'label'  => 'Baiduspider',
			'ua'     => 'baiduspider',
			'verify' => 'rdns',
			'rdns'   => ['.baidu.com'],
		],
		'petal' => [
			'label'  => 'PetalBot',
			'ua'     => 'petalbot',
			'verify' => 'rdns',
			'rdns'   => ['.petalsearch.com', '.huawei.com'],
		],

		// SEO-краулери (зазвичай корисні; rDNS у них не завжди стабільний → UA-режим)
		'ahrefs' => [
			'label'  => 'AhrefsBot',
			'ua'     => 'ahrefsbot',
			'verify' => 'ua',
			'rdns'   => [],
		],
		'semrush' => [
			'label'  => 'SemrushBot',
			'ua'     => 'semrush(bot)?',
			'verify' => 'ua',
			'rdns'   => [],
		],
		'dotbot' => [
			'label'  => 'DotBot (Moz)',
			'ua'     => 'dotbot',
			'verify' => 'ua',
			'rdns'   => [], // інколи .moz.com/.mozaws.net, але нестабільно
		],
		'mj12' => [
			'label'  => 'MJ12bot (Majestic)',
			'ua'     => 'mj12bot',
			'verify' => 'ua',
			'rdns'   => [],
		],
		'sogou' => [
			'label'  => 'Sogou',
			'ua'     => 'sogou',
			'verify' => 'ua',
			'rdns'   => [],
		],
		'exabot' => [
			'label'  => 'Exabot',
			'ua'     => 'exabot',
			'verify' => 'ua',
			'rdns'   => [],
		],
		'seznam' => [
			'label'  => 'SeznamBot',
			'ua'     => 'seznambot',
			'verify' => 'ua',
			'rdns'   => [],
		],
		'qwant' => [
			'label'  => 'Qwantify',
			'ua'     => 'qwantify',
			'verify' => 'ua',
			'rdns'   => [],
		],
		'ccbot' => [
			'label'  => 'CCBot (CommonCrawl)',
			'ua'     => 'ccbot|commoncrawl',
			'verify' => 'ua', // працюють із AWS; rDNS не надійний
			'rdns'   => [],
		],
		'bytespider' => [
			'label'  => 'Bytespider',
			'ua'     => 'bytespider',
			'verify' => 'ua',
			'rdns'   => [],
		],

		// AI/ресерч
		'gptbot' => [
			'label'  => 'GPTBot / ChatGPT-User',
			'ua'     => 'gptbot|chatgpt-user',
			'verify' => 'ua',
			'rdns'   => [],
		],
		'claude' => [
			'label'  => 'ClaudeBot / anthropic-ai',
			'ua'     => 'claudebot|anthropic-ai',
			'verify' => 'ua',
			'rdns'   => [],
		],
		'perplexity' => [
			'label'  => 'PerplexityBot',
			'ua'     => 'perplexitybot',
			'verify' => 'ua',
			'rdns'   => [],
		],
		'phind' => [
			'label'  => 'PhindBot',
			'ua'     => 'phindbot',
			'verify' => 'ua',
			'rdns'   => [],
		],
		'omgili' => [
			'label'  => 'Omgili/Omgilibot',
			'ua'     => 'omgili|omgilibot',
			'verify' => 'ua',
			'rdns'   => [],
		],
	];

	/** Дозволяємо іншим додати/змінити реєстр */
	return apply_filters('crit_bots_registry', $bots);
}

/** Зчитування опцій: повертає масив ключів ботів, що увімкнені */
function crit_bot_opts(): array {
	$enabled = get_option('crit_allow_bots', []);
	if (!is_array($enabled)) $enabled = [];

	// Back-compat: старі опції google/bing
	$legacy_g = get_option('crit_allow_googlebot', '0');
	$legacy_b = get_option('crit_allow_bingbot', '0');
	if ($legacy_g === '1' || $legacy_g === 1) $enabled[] = 'google';
	if ($legacy_b === '1' || $legacy_b === 1) $enabled[] = 'bing';

	// нормалізувати ключі
	$enabled = array_values(array_unique(array_map('sanitize_key', $enabled)));
	return $enabled;
}

/** Повертає список ботів, які матчаться по UA (без перевірки rDNS) */
function crit_bots_matched_for_ua(string $ua_raw): array {
	$out = [];
	if ($ua_raw === '') return $out;
	$ua = $ua_raw;
	foreach (crit_bots_registry() as $key => $bot) {
		$rx = '~' . $bot['ua'] . '~i';
		if (@preg_match($rx, $ua) && preg_match($rx, $ua)) {
			$out[] = $key;
		}
	}
	return $out;
}

/** Строга перевірка rDNS (reverse + forward) під дозволені суфікси */
function crit_bot_verify_rdns(string $ip, array $suffixes): bool {
	$host = @gethostbyaddr($ip);
	if (!$host) return false;
	$ok_suffix = false;
	foreach ($suffixes as $suf) {
		if ($suf !== '' && preg_match('~' . preg_quote($suf, '~') . '$~i', $host)) { $ok_suffix = true; break; }
	}
	if (!$ok_suffix) return false;

	if (!function_exists('dns_get_record')) return false;
	$A    = dns_get_record($host, DNS_A);
	$AAAA = dns_get_record($host, DNS_AAAA);
	$recs = array_merge(is_array($A)?$A:[], is_array($AAAA)?$AAAA:[]);
	foreach ($recs as $r) {
		$rip = $r['ip'] ?? ($r['ipv6'] ?? null);
		if ($rip && strcasecmp($rip, $ip) === 0) return true;
	}
	return false;
}

/** Чи дозволений поточний запит (будь-який з увімкнених ботів пройшов перевірку) */
function crit_is_allowed_bot(): bool {
	$enabled = crit_bot_opts();
	if (!$enabled) return false;

	$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
	if ($ua === '') return false;

	// Використовуємо реальний IP (враховує X-Forwarded-For / CF-Connecting-IP)
	// REMOTE_ADDR може бути IP проксі — тоді rDNS-перевірка Googlebot завжди провалюється
	$ip = function_exists('crit_geoblock_client_ip')
		? crit_geoblock_client_ip()
		: (string) ($_SERVER['REMOTE_ADDR'] ?? '');

	if ($ip === '') return false;

	$reg = crit_bots_registry();
	$candidates = [];
	foreach ($enabled as $key) {
		if (!isset($reg[$key])) continue;
		$rx = '~' . $reg[$key]['ua'] . '~i';
		if (@preg_match($rx, $ua) && preg_match($rx, $ua)) {
			$candidates[] = $key;
		}
	}
	if (!$candidates) return false;

	// Кешуємо по IP+списку кандидатів (стабільно на час сесії/доби)
	$ckey = 'crit_bot_ok_' . md5($ip . '|' . implode(',', $candidates));
	$cached = get_transient($ckey);
	if ($cached !== false) return (bool)$cached;

	$ok = false;
	foreach ($candidates as $key) {
		$bot = $reg[$key];
		if (($bot['verify'] ?? 'ua') === 'rdns') {
			if (crit_bot_verify_rdns($ip, (array)($bot['rdns'] ?? []))) { $ok = true; break; }
		} else {
			// лише UA — менш безпечно; але дозволяємо, якщо увімкнено в налаштуваннях
			$ok = true; break;
		}
	}

	set_transient($ckey, $ok ? 1 : 0, CRIT_BOT_TTL);
	return $ok;
}

/** Записати/прибрати блок UA-вийнятків у .htaccess для всіх увімкнених ботів */
function crit_apply_bot_htaccess_policy(): bool {
	$enabled = crit_bot_opts();
	$reg     = crit_bots_registry();

	// Використовуємо crit_ht_get_path() з htaccess-blocklist.php — коректно
	// враховує subdirectory WordPress install через get_home_path().
	// Fallback на ABSPATH якщо функція ще не завантажена.
	$path = function_exists('crit_ht_get_path')
		? crit_ht_get_path()
		: ABSPATH . '.htaccess';

	if (!file_exists($path) || !is_readable($path)) return false;
	if (!is_writable($path)) return false;

	$raw = (string) @file_get_contents($path);
	$begin = "# BEGIN CRIT-BOT-ALLOW";
	$end   = "# END CRIT-BOT-ALLOW";

	$lines = [];
	if ($enabled) {
		$lines[] = $begin;
		$lines[] = "<IfModule mod_setenvif.c>";
		foreach ($enabled as $key) {
			if (!isset($reg[$key])) continue;
			$env = 'CRIT_ALLOW_' . strtoupper($key);
			$ua  = $reg[$key]['ua'];
			// SetEnvIfNoCase приймає regex; не вставляємо лапки всередині $ua
			$lines[] = '    SetEnvIfNoCase User-Agent "' . $ua . '" ' . $env . '=1';
		}
		$lines[] = "</IfModule>";
		$lines[] = $end;
	}

	$snippet = $lines ? implode(PHP_EOL, $lines) . PHP_EOL : '';
	$has = preg_match("~^".preg_quote($begin,"~").".*?".preg_quote($end,"~")."\\s*$~ms", $raw);

	if ($snippet === '') {
		$new = preg_replace("~^".preg_quote($begin,"~").".*?".preg_quote($end,"~")."\\s*$~ms", "", $raw);
	} else {
		if ($has) {
			$new = preg_replace("~^".preg_quote($begin,"~").".*?".preg_quote($end,"~")."\\s*$~ms", $snippet, $raw);
		} else {
			$new = rtrim($raw) . PHP_EOL . $snippet;
		}
	}

	$bak = $path . '.bak-' . gmdate('Ymd-His');
	@copy($path, $bak); // бекап

	// Прибираємо старі бекапи, лишаємо максимум 3 (можна змінити через CRIT_BOT_BAK_KEEP або фільтр)
	crit_prune_htaccess_backups($path, CRIT_BOT_BAK_KEEP);

	$ok = @file_put_contents($path, $new, LOCK_EX);

	return $ok !== false;
}

/** Адмін-UI */
add_action('admin_menu', function(){
	add_submenu_page(
		'critical-event-logs',
		'Пошукові боти — винятки',
		'Боти-винятки',
		'manage_options',
		'crit-bots-allow',
		'crit_bots_allow_page'
	);
}, 99);

function crit_bots_allow_page() {
	if (!current_user_can('manage_options')) return;

	$reg   = crit_bots_registry();
	$ua    = (string) ($_SERVER['HTTP_USER_AGENT'] ?? '');
	// Реальний IP (враховує проксі) — той самий що використовує crit_is_allowed_bot()
	$ip    = function_exists('crit_geoblock_client_ip')
		? crit_geoblock_client_ip()
		: (string) ($_SERVER['REMOTE_ADDR'] ?? '');
	$match = crit_bots_matched_for_ua($ua);

	// Save
	if (isset($_POST['crit_bots_save'])) {
		check_admin_referer('crit_bots_allow_save','crit_bots_nonce');

		$selected = [];
		if (!empty($_POST['crit_allow_bots']) && is_array($_POST['crit_allow_bots'])) {
			foreach ($_POST['crit_allow_bots'] as $key => $on) {
				$key = sanitize_key($key);
				if (isset($reg[$key])) $selected[] = $key;
			}
		}
		update_option('crit_allow_bots', $selected);

		// Back-compat записати старі опції
		update_option('crit_allow_googlebot', in_array('google',$selected,true) ? '1' : '0');
		update_option('crit_allow_bingbot',   in_array('bing',$selected,true)   ? '1' : '0');

		$ok = crit_apply_bot_htaccess_policy();
		echo $ok
			? '<div class="notice notice-success"><p>✅ Збережено. .htaccess оновлено.</p></div>'
			: '<div class="notice notice-warning"><p>ℹ️ Налаштування збережено, але .htaccess не оновлено (немає доступу для запису). Додайте блок вручну: <code># BEGIN CRIT-BOT-ALLOW ... # END CRIT-BOT-ALLOW</code>.</p></div>';

		// invalidate діагностики
		$match = crit_bots_matched_for_ua($ua);
	}

	$enabled = crit_bot_opts();
	$is_ok   = crit_is_allowed_bot() ? 'так' : 'ні';

	echo '<div class="wrap"><h1>Пошукові боти — винятки</h1>';
	echo '<p>Дозволяє обраним ботам індексувати сайт, навіть якщо IP у <code>.htaccess</code> заблоковано або увімкнено GeoBlock. ';
	echo 'Для GeoBlock використовується перевірка справжності (reverse+forward DNS) там, де це можливо. ';
	echo 'Деякі боти можуть бути дозволені лише за UA (менш безпечно) — такі позначені <em>UA-only</em>.</p>';

	// Форма
	echo '<form method="post">';
	wp_nonce_field('crit_bots_allow_save','crit_bots_nonce');

	echo '<table class="widefat striped" style="max-width:900px">';
	echo '<thead><tr><th style="width:60px">Увімк.</th><th>Бот</th><th>Перевірка</th><th>UA-шаблон</th></tr></thead><tbody>';
	foreach ($reg as $key => $bot) {
		$on  = in_array($key, $enabled, true);
		$lbl = esc_html($bot['label']);
		$verify = ($bot['verify']==='rdns') ? 'rDNS (строго)' : 'UA-only';
		$ua_rx  = esc_html($bot['ua']);
		echo '<tr>';
		echo '<td><label><input type="checkbox" name="crit_allow_bots['.esc_attr($key).']" value="1" '.checked($on,true,false).'></label></td>';
		echo '<td><strong>'. $lbl .'</strong> <code>'. esc_html($key) .'</code></td>';
		echo '<td>'. esc_html($verify) .'</td>';
		echo '<td><code>'. $ua_rx .'</code></td>';
		echo '</tr>';
	}
	echo '</tbody></table>';

	echo '<p><button class="button button-primary" name="crit_bots_save" value="1">Зберегти</button></p>';
	echo '</form>';

	// Діагностика
	echo '<hr><h2>Діагностика поточного запиту</h2>';
	echo '<p><strong>UA:</strong> '. esc_html($ua) .'<br>';
	echo '<strong>IP:</strong> '. esc_html($ip) .'<br>';
	echo '<strong>Матчі за UA:</strong> '. ($match ? esc_html(implode(', ', array_map(function($k) use ($reg){ return $reg[$k]['label'] ?? $k; }, $match))) : '—') . '<br>';
	echo '<strong>Розпізнано як дозволеного бота (з урахуванням перевірки):</strong> <span style="font-weight:bold">'. $is_ok .'</span></p>';

	echo '<p><small>Порада: щоб виняток працював і у <code>.htaccess</code>, потрібен доступ на запис до цього файлу. ';
	echo 'GeoBlock перевіряє справжність ботів (де можливо) через rDNS, тож підроблений UA не пройде GeoBlock.</small></p>';

	echo '</div>';
}