<?php
/**
 * Plugin Name: Critical Event Logger
 * Plugin URI: https://github.com/fly380/critical-event-logger
 * Description: Логування критичних подій із швидким AJAX-переглядом, парсером «склеєних» рядків, частотністю IP, Geo/пул-визначенням, ручним блокуванням (.htaccess для Apache 2.2/2.4), ротацією й очищенням логів, GeoBlock та опційними AI-інсайтами.
 * Version: 2.1.2
 * Author: Казмірчук Андрій
 * Author URI: https://www.facebook.com/fly380/
 * Text Domain: fly380
 * Requires PHP: 7.2
 * Requires at least: 5.8
 * Tested up to: 6.8
 * License: GPLv2 or later
 * Plugin URI: https://github.com/fly380/critical-event-logger
 * Update URI: https://github.com/fly380/critical-event-logger
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Domain Path: /languages
 * Copyright © 2025 Казмірчук Андрій
 */
if ( is_admin() ) {
	// Підключаємо PUC (Composer або локальна папка)
	if ( file_exists( __DIR__ . '/vendor/autoload.php' ) ) {
		require_once __DIR__ . '/vendor/autoload.php';
	} elseif ( file_exists( __DIR__ . '/plugin-update-checker/plugin-update-checker.php' ) ) {
		require_once __DIR__ . '/plugin-update-checker/plugin-update-checker.php';
	}

	if ( class_exists(\YahnisElsts\PluginUpdateChecker\v5\PucFactory::class) ) {
		$updateChecker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
			'https://github.com/fly380/critical-event-logger', // репозиторій GitHub
			__FILE__,                                          // головний файл плагіна
			'critical-event-logger'                            // slug плагіна
		);

		// ✅ Опційна автентифікація до GitHub, щоб уникнути 403 (rate limit).
		// Можеш задати define('CRIT_GITHUB_TOKEN','ghp_xxx') у wp-config.php
		// або зберігати токен в опції 'crit_github_token'.
		$ghToken = defined('CRIT_GITHUB_TOKEN') ? CRIT_GITHUB_TOKEN : ( get_option('crit_github_token') ?: '' );
		if ( is_string($ghToken) && $ghToken !== '' ) {
			$updateChecker->setAuthentication( trim($ghToken) );
		}

		// ✅ Безпечний виклик release assets
		$api = $updateChecker->getVcsApi();
		if ( $api && method_exists($api, 'enableReleaseAssets') ) {
			$api->enableReleaseAssets();
		}

		// Відстежуємо гілку
		$updateChecker->setBranch('main');

		// ---- Локальні іконки/банери ----
		$assetsUrl  = plugin_dir_url(__FILE__)  . 'assets/';
		$assetsPath = plugin_dir_path(__FILE__) . 'assets/';

		$icons = [];
		if ( file_exists($assetsPath . 'icon-128x128.png') ) { $icons['1x'] = $assetsUrl . 'icon-128x128.png'; }
		if ( file_exists($assetsPath . 'icon-256x256.png') ) { $icons['2x'] = $assetsUrl . 'icon-256x256.png'; }

		$banners = [];
		if ( file_exists($assetsPath . 'banner-772x250.png') )  { $banners['low']  = $assetsUrl . 'banner-772x250.png'; }
		if ( file_exists($assetsPath . 'banner-1544x500.png') ) { $banners['high'] = $assetsUrl . 'banner-1544x500.png'; }

		// 1) Модалка "Переглянути деталі версії"
		$updateChecker->addResultFilter(function($info) use ($icons, $banners) {
			if (!empty($icons))   { $info->icons   = array_merge((array)($info->icons ?? []),   $icons); }
			if (!empty($banners)) { $info->banners = array_merge((array)($info->banners ?? []), $banners); }
			return $info;
		});

		// 2) Рядок оновлення у списку плагінів
		$updateChecker->addFilter('pre_inject_update', function($update) use ($icons, $banners) {
			if ($update) {
				if (!empty($icons))   { $update->icons   = $icons; }
				if (!empty($banners)) { $update->banners = $banners; }
			}
			return $update;
		});

		// 3) Підстраховка: доклеїти у transient, якщо щось перетреться
		add_filter('site_transient_update_plugins', function($transient) use ($icons, $banners) {
			$pluginFile = plugin_basename(__FILE__);
			if ( isset($transient->response[$pluginFile]) ) {
				if (!empty($icons)   && empty($transient->response[$pluginFile]->icons))   { $transient->response[$pluginFile]->icons   = $icons; }
				if (!empty($banners) && empty($transient->response[$pluginFile]->banners)) { $transient->response[$pluginFile]->banners = $banners; }
			}
			return $transient;
		});
	}
}


/**
 * Будує HTML changelog із джерел у такому порядку:
 * 1) CHANGELOG.md (Markdown → HTML)
 * 2) Секція "== Changelog ==" у readme.txt (WP-readme → HTML)
 * 3) Тіло останнього релізу GitHub (Markdown → HTML; якщо url-encoded — розкодуємо)
 */
function crit_build_changelog_html_from_repo($updateChecker) {
	$api = $updateChecker->getVcsApi();
	if (!$api) return '';

	// 1) CHANGELOG.md
	$md = $api->getRemoteFile('CHANGELOG.md');
	if (is_string($md) && trim($md) !== '') {
		return crit_md_to_html_tiny($md);
	}

	// 2) readme.txt → секція "Changelog"
	$readme = $api->getRemoteFile('readme.txt');
	if (is_string($readme) && trim($readme) !== '') {
		$section = crit_readme_extract_changelog_section($readme);
		if ($section !== '') {
			return crit_wp_readme_to_html($section);
		}
	}

	// 3) GitHub Release body
	try {
		if (method_exists($api, 'getLatestRelease')) {
			$rel = $api->getLatestRelease(); // масив або null
			if (is_array($rel) && !empty($rel['body'])) {
				$body = $rel['body'];
				if (strpos($body, '%0A') !== false || strpos($body, '%') !== false) {
					// Буває url-encoded – розкодовуємо акуратно
					$decoded = @rawurldecode($body);
					if (is_string($decoded) && $decoded !== '') { $body = $decoded; }
				}
				return crit_md_to_html_tiny($body);
			}
		}
	} catch (\Throwable $e) {
		// тихо ігноруємо
	}

	return '';
}

/**
 * Дуже легкий Markdown→HTML: H1/H2/H3, списки, параграфи.
 * Додатково: ігноруємо H1 "# Changelog" аби не створював великий верхній відступ.
 */
function crit_md_to_html_tiny($md) {
	$md = ltrim(preg_replace("/\r\n?/", "\n", (string)$md)); // ltrim — зрізає верхні порожні рядки/BOM
	$lines = explode("\n", $md);
	$html = '';
	$inList = false;

	foreach ($lines as $line) {
		$t = rtrim($line);

		// Ігноруємо H1 "Changelog", щоб не плодити зайвий відступ у модалці
		if (preg_match('/^#\s*changelog\s*$/ui', $t)) {
			continue;
		}

		if ($t === '') {
			if ($inList) { $html .= "</ul>\n"; $inList = false; }
			continue;
		}
		if (preg_match('/^###\s*(.+)$/u', $t, $m)) {
			if ($inList) { $html .= "</ul>\n"; $inList = false; }
			$html .= '<h3>' . esc_html($m[1]) . "</h3>\n";
			continue;
		}
		if (preg_match('/^##\s*(.+)$/u', $t, $m)) {
			if ($inList) { $html .= "</ul>\n"; $inList = false; }
			$html .= '<h2>' . esc_html($m[1]) . "</h2>\n";
			continue;
		}
		if (preg_match('/^#\s*(.+)$/u', $t, $m)) { // Якщо все ж є H1 — відобразимо компактно
			if ($inList) { $html .= "</ul>\n"; $inList = false; }
			$html .= '<h2>' . esc_html($m[1]) . "</h2>\n";
			continue;
		}
		if (preg_match('/^\s*[-*]\s+(.+)$/u', $t, $m)) {
			if (!$inList) { $html .= "<ul>\n"; $inList = true; }
			$html .= '<li>' . esc_html($m[1]) . "</li>\n";
			continue;
		}
		$html .= '<p>' . esc_html($t) . "</p>\n";
	}

	if ($inList) { $html .= "</ul>\n"; }
	// Ще раз підчистимо верхні пустоти що могли прослизнути
	$html = preg_replace('~^(?:\s|<p>\s*&nbsp;\s*</p>)+~i', '', $html);
	return trim($html);
}

/**
 * Витягає секцію "== Changelog ==" із readme.txt (WP-формат).
 */
function crit_readme_extract_changelog_section($readmeTxt) {
	if (!is_string($readmeTxt) || $readmeTxt === '') return '';
	if (!preg_match('~==\s*Changelog\s*==\s*(.+)$~is', $readmeTxt, $m)) return '';
	$sec = $m[1];
	// усе до наступної секції верхнього рівня "== ... =="
	$parts = preg_split('~\n==\s*[^\n]+==~', $sec, 2);
	return trim($parts[0] ?? '');
}

/**
 * Примітивний конвертер WP-readme секції у HTML (заголовки = ... =, жирний, списки).
 */
function crit_wp_readme_to_html($section) {
	$txt = str_replace(["\r\n", "\r"], "\n", (string)$section);
	// = 2.1.2 = → <h2>..., **text** → <strong>...</strong>
	$txt = preg_replace_callback('~^\s*=\s*(.+?)\s*=\s*$~m', function($m){ return "\n<h2>" . esc_html($m[1]) . "</h2>\n"; }, $txt);
	$txt = preg_replace('~\*\*(.+?)\*\*~s', '<strong>$1</strong>', $txt);

	$lines = explode("\n", $txt);
	$html = ''; $inList = false;
	foreach ($lines as $line) {
		if (preg_match('~^\s*[\*\-]\s+(.+)$~', $line, $m)) {
			if (!$inList) { $html .= "<ul>\n"; $inList = true; }
			$html .= '<li>' . esc_html($m[1]) . "</li>\n";
		} else {
			if ($inList) { $html .= "</ul>\n"; $inList = false; }
			if (trim($line) !== '') { $html .= '<p>' . esc_html($line) . "</p>\n"; }
		}
	}
	if ($inList) { $html .= "</ul>\n"; }

	return trim($html);
}


/* Підключаємо основні файли плагіна */
require_once plugin_dir_path(__FILE__) . 'logger.php';
require_once plugin_dir_path(__FILE__) . 'logger-hooks.php';
if (file_exists(plugin_dir_path(__FILE__) . 'privacy.php')) {
	require_once plugin_dir_path(__FILE__) . 'privacy.php';
}

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

	$fp = fopen($file, 'rb');
	if ($fp === false) {
		crit_log_internal("Unable to fopen for reading: {$file}");
		return [];
	}

	$filesize = filesize($file);
	if ($filesize === false || $filesize <= 0) {
		fclose($fp);
		return [];
	}

	// читаємо не більше 1 МБ з хвоста
	$read = min($filesize, 1024 * 1024);

	if ($read > 0) {
		// перейти на $read байтів від кінця
		if (fseek($fp, -$read, SEEK_END) !== 0) {
			// якщо з якоїсь причини не вдалося — fallback на початок
			fseek($fp, 0, SEEK_SET);
			$read = $filesize;
		}
		$chunk = fread($fp, $read);
		if ($chunk === false) {
			crit_log_internal("fread failed on {$file}");
			$chunk = '';
		}
	} else {
		$chunk = '';
	}

	fclose($fp);

	if ($chunk === '') return [];
	$entries = crit_split_log_entries($chunk);
	return array_slice($entries, -$limit);
}

// Градієнт підсвітки за частотою появи IP: 11..49 → від помаранчевого до червоного, 50+ → червоний + жирний
if (!function_exists('crit_heat_style_from_count')) {
	function crit_heat_style_from_count(int $cnt, int $min = 10, int $max = 50, int $boldAt = 50): string {
		if ($cnt <= $min) return '';
		$clamped = min($max, max($cnt, $min));
		$t = ($clamped - $min) / ($max - $min); // 0..1
		$h = (int) round(30 - 30 * $t);         // 30° (помаранч) → 0° (червоний)
		$s = 85;                                 // насиченість
		$l = (int) round(45 - 5 * $t);           // легка зміна яскравості
		$style = "color:hsl({$h}deg, {$s}%, {$l}%);";
		if ($cnt >= $boldAt) $style .= 'font-weight:bold;';
		return $style;
	}
}

// Централізований час для логів (локальний TZ сайту WP)
if (!function_exists('crit_log_time')) {
	function crit_log_time(string $format = 'Y-m-d H:i:s'): string {
		// WP 5.3+ — поважає таймзону з налаштувань сайту
		if (function_exists('wp_date')) {
			return wp_date($format);
		}
		// Фолбек, якщо wp_date недоступний
		return date($format);
	}
}

// === BOT DETECTION HELPERS ===
if (!function_exists('crit_bot_match_ua')) {
	function crit_bot_match_ua(string $ua): ?array {
		$ua_l = strtolower($ua);

		$patterns = [
			'Googlebot'      => 'googlebot|adsbot-google|apis-google|mediapartners-google|feedfetcher-google|duplexweb-google',
			'Bingbot'        => 'bingbot|adidxbot|msnbot',
			'DuckDuckBot'    => 'duckduckbot|duckduckgo',
			'Baidu'          => 'baiduspider',
			'Yandex'         => 'yandex(bot|images|media|mobile|news|video|image|accessibility|metrika)',
			'Applebot'       => 'applebot',
			'PetalBot'       => 'petalbot',
			'AhrefsBot'      => 'ahrefsbot',
			'SemrushBot'     => 'semrush(bot)?',
			'DotBot'         => 'dotbot',
			'MJ12bot'        => 'mj12bot',
			'Sogou'          => 'sogou',
			'Exabot'         => 'exabot',
			'SeznamBot'      => 'seznambot',
			'Qwantify'       => 'qwantify',
			'CCBot'          => 'ccbot|commoncrawl',
			'Bytespider'     => 'bytespider',
			// AI/ресерч краулери
			'GPTBot'         => 'gptbot|chatgpt-user',
			'ClaudeBot'      => 'claudebot|anthropic-ai',
			'PerplexityBot'  => 'perplexitybot',
			'PhindBot'       => 'phindbot',
			'Omgili'         => 'omgili|omgilibot',
			// Соціальні/прев’ю
			'Facebook'       => 'facebookexternalhit|facebot',
			'Twitter'        => 'twitterbot',
			'LinkedIn'       => 'linkedinbot',
			'Slack'          => 'slackbot',
			'Telegram'       => 'telegrambot',
			'Discord'        => 'discordbot',
			'WhatsApp'       => 'whatsapp',
			'Pinterest'      => 'pinterestbot',
			// Headless / інструменти / скрейпери / бібліотеки
			'Headless'       => 'headlesschrome|puppeteer|playwright|phantomjs|lighthouse|pagespeed',
			'Libraries'      => 'curl|wget|python-requests|go-http-client|libwww-perl|okhttp|aiohttp|httpx|httpclient|java|scrapy|guzzlehttp',
			// Моніторинги/аптайм
			'Monitor'        => 'uptimerobot|pingdom|statuscake|newrelicpinger|datadog|nagios|zabbix|site24x7',
		];

		foreach ($patterns as $name => $re) {
			if (preg_match('~(?:' . $re . ')~i', $ua)) {
				return ['name' => $name, 'generic' => false];
			}
		}

		// fallback: загальні індикатори
		if (preg_match('~\b(bot|spider|crawler|fetcher|analyz|scrap|preview|transcoder)\b~i', $ua)) {
			return ['name' => 'GenericBot', 'generic' => true];
		}
		return null;
	}
}

if (!function_exists('crit_verify_search_engine_bot')) {
	function crit_verify_search_engine_bot(string $ip, string $botName): string {
		$botName = strtolower($botName);
		$host = @gethostbyaddr($ip);
		if (!$host || $host === $ip) return 'na';

		$okSuffix = null;
		if ($botName === 'googlebot')          $okSuffix = '.googlebot.com';
		elseif ($botName === 'bingbot')        $okSuffix = '.search.msn.com';
		elseif ($botName === 'yandex')         $okSuffix = '.yandex.ru|.yandex.net';
		elseif ($botName === 'baidu')          $okSuffix = '.baidu.com';
		elseif ($botName === 'duckduckbot')    $okSuffix = '.duckduckgo.com';
		elseif ($botName === 'applebot')       $okSuffix = '.applebot.apple.com';

		if (!$okSuffix) return 'na';

		$ok = false;
		foreach (explode('|', $okSuffix) as $suf) {
			if (substr($host, -strlen($suf)) === $suf) { $ok = true; break; }
		}
		if (!$ok) return 'bad';

		// forward-confirm
		$ip2 = @gethostbyname($host);
		return ($ip2 === $ip) ? 'ok' : 'bad';
	}
}

if (!function_exists('crit_capture_client_ua')) {
	function crit_capture_client_ua(): void {
		$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
		if ($ua === '') return;

		$ip = function_exists('crit_client_ip')
			? crit_client_ip()
			: ($_SERVER['REMOTE_ADDR'] ?? '');
		if ($ip === '') return;

		$match = crit_bot_match_ua($ua);
		$bot   = $match ? $match['name'] : '';
		$ver   = 'na';

		if ($bot) {
			// verify тільки для «великих» пошуковиків
			$core = ['googlebot','bingbot','yandex','baidu','duckduckbot','applebot'];
			if (in_array(strtolower($bot), $core, true)) {
				$ver = crit_verify_search_engine_bot($ip, $bot);
			}
		}

		$data = [
			'ua'  => $ua,
			'bot' => $bot,
			'ver' => $ver,
			'ts'  => time(),
		];
		set_transient('crit_ua_' . md5($ip), $data, 12 * HOUR_IN_SECONDS);

		// ── ДОДАНО: маркер у лог про виявленого бота ──
		if (!empty($bot) && function_exists('crit_log_time')) {
			$log_file = crit_log_file();
			if ($log_file) {
				$msg = '[' . crit_log_time() . '][' . $ip . '][guest][INFO] BOT DETECTED: ' . $bot . '; UA=' . substr($ua, 0, 180);
				crit_append_log_line($log_file, $msg);
			}
		}
	}
	add_action('init', 'crit_capture_client_ua', 1);
}


/**
 * Акуратно дописує рядок у лог: гарантує перенос перед новим записом і додає \n в кінці
 * $line очікується БЕЗ \n в кінці.
 */
function crit_append_log_line(string $file, string $line): void {
	$line = rtrim($line, "\r\n");

	// Маскуємо лише якщо увімкнено опцію
	$sanitize_on = (get_option('crit_log_sanitize', '0') === '1');

	if ($sanitize_on) {
		if (function_exists('crit_sanitize_log_line_structured')) {
			// Структурний санітайзер сам знає, що саме маскувати
			$line = crit_sanitize_log_line_structured($line);
		} else {
			// Обережний фолбек: маскуємо ТІЛЬКИ username і message, не чіпаючи [IP]
			if (
				function_exists('crit_sanitize_text') &&
				preg_match('/^\[([0-9\- :]+)\]\[([^\]]+)\]\[([^\]]*)\]\[([^\]]+)\]\s?(.*)$/', $line, $m)
			) {
				$time     = $m[1];
				$ip       = $m[2];                 // важливо: не маскуємо, щоб не зламати аналіз
				$username = crit_sanitize_text($m[3]);
				$level    = strtoupper(trim($m[4]));
				$message  = crit_sanitize_text($m[5]);

				$line = '['.$time.']['.$ip.']['.$username.']['.$level.'] '.$message;
			}
			// Якщо формат інший — залишаємо як є (UI все одно маскує при виводі)
		}
	}

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
	$result = file_put_contents($file, $prefix . $line . "\n", FILE_APPEND | LOCK_EX);
	if ($result === false) {
		crit_log_internal("file_put_contents failed (append) for {$file}");
	}
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
// === AJAX: загальна кількість записів у логу ===
add_action('wp_ajax_critical_logger_total_count', 'critical_logger_total_count_cb');
function critical_logger_total_count_cb() {
	if ( ! current_user_can('manage_options') ) {
		wp_send_json_error('Недостатньо прав', 403);
	}
	check_ajax_referer('critical_logger_simple_nonce', 'nonce');

	$log_file = crit_log_file();
	$count = file_exists($log_file) ? crit_count_entries_in_file($log_file) : 0;

	wp_send_json_success(['count' => (int)$count]);
}

/* === AJAX: Виявлені IP (за частотою) === */
add_action('wp_ajax_critical_logger_detected_ips', 'critical_logger_detected_ips_cb');
function critical_logger_detected_ips_cb() {
	if (! current_user_can('manage_options')) wp_send_json_error('Недостатньо прав', 403);
	check_ajax_referer('critical_logger_simple_nonce', 'nonce');

	$log_file = crit_log_file();
	if (! file_exists($log_file)) wp_send_json_error('Лог-файл не знайдено', 404);

	$entries   = crit_tail_entries($log_file, 2000);
	$ip_counts = [];
	foreach ($entries as $ln) {
		if (preg_match('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $ln, $m)) {
			$ip_counts[$m[0]] = ($ip_counts[$m[0]] ?? 0) + 1;
		}
	}
	arsort($ip_counts);

	ob_start();
	if ($ip_counts) {
		echo '<table class="widefat striped" style="width:100%;">';
		echo '<thead><tr>
			<th>IP</th>
			<th>Пул</th>
			<th>Гео</th>
			<th>Дія</th>
		</tr></thead><tbody>';

		foreach ($ip_counts as $fip => $cnt) {
			$style = crit_heat_style_from_count((int)$cnt); // лишаємо підсвітку за частотою

			echo '<tr>';
			echo '<td style="' . esc_attr($style) . '">' . esc_html($fip) . '</td>';
			echo '<td class="crit-pool" data-ip="' . esc_attr($fip) . '"><em style="color:#888">…</em></td>';
			echo '<td class="crit-geo" data-ip="' . esc_attr($fip) . '"><em style="color:#888">…</em></td>';
			echo '<td>';

			// Кнопка "Блокувати IP"
			echo '<form method="post" style="display:inline; margin-right:4px;">' .
				 wp_nonce_field('manual_block_ip_action', 'manual_block_ip_nonce', true, false) .
				 '<input type="hidden" name="manual_ip_address" value="' . esc_attr($fip) . '">' .
				 '<input type="submit" name="manual_block_ip" class="button button-small" value="Блокувати">' .
			'</form>';

			// Кнопка "Блокувати пул" (значення підставить AJAX після geo/pool lookup)
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

	$log_file = crit_log_file();
	if ( ! file_exists($log_file) ) wp_send_json_error('Лог-файл не знайдено', 404);

	$limit  = isset($_POST['limit']) ? max(50, min(2000, intval($_POST['limit']))) : 500;

	// Приймаємо список дозволених рівнів (масив), спец-значення "__OTHER__" означає "всі інші"
	$levels = isset($_POST['levels']) ? (array) $_POST['levels'] : [];
	$levels = array_slice(array_map('sanitize_text_field', $levels), 0, 50);
	$levels = array_values(array_filter($levels, static function($v){ return $v !== ''; }));

	// Популярні рівні (щоб відрізнити "Інше")
	$known_levels = [
		'INFO','WARNING','WARN','ERROR','NOTICE','FATAL','DEPRECATED','SCAN',
		'USER NOTICE','USER ERROR',
		'CORE ERROR','CORE WARNING',
		'COMPILE ERROR','COMPILE WARNING',
		'PARSE ERROR','STRICT','RECOVERABLE ERROR'
	];
	$known_map = array_flip($known_levels);

	$want_other = in_array('__OTHER__', $levels, true);

	// Будуємо карту дозволених і враховуємо синоніми (WARNING ⇄ WARN)
	$allow_map = array_flip(array_diff($levels, ['__OTHER__']));
	if (isset($allow_map['WARN']) && !isset($allow_map['WARNING'])) $allow_map['WARNING'] = true;
	if (isset($allow_map['WARNING']) && !isset($allow_map['WARN'])) $allow_map['WARN'] = true;

	$lines = crit_tail_entries($log_file, $limit);

	// Чи вмикати маскування у виводі
	$sanitize_on = (get_option('crit_log_sanitize','0') === '1') && function_exists('crit_sanitize_text');

	ob_start();

	echo '<table class="widefat fixed striped" style="width:100%;">';
	echo '<thead><tr><th>Час</th><th>IP</th><th>Користувач</th><th>Рівень</th><th>Повідомлення</th><th>Дія</th></tr></thead><tbody>';

	$ip_counts = []; // для підсвічування частих IP
	foreach ($lines as $ln) {
		if (preg_match('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $ln, $m_ip)) {
			$ip_counts[$m_ip[0]] = ($ip_counts[$m_ip[0]] ?? 0) + 1;
		}
	}

	// показуємо від нових до старих
	foreach (array_reverse($lines) as $line) {
		$time = $ip = $username = $level = $message = '';

		if (preg_match('/^\[([0-9\- :]+)\]\[([^\]]+)\]\[([^\]]*)\]\[([^\]]+)\]\s?(.*)$/', $line, $m)) {
			$time     = $m[1];
			$ip       = $m[2];
			$username = $m[3];
			$level    = strtoupper(trim($m[4]));
			$message  = $m[5];
		} elseif (preg_match('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $line, $mm)) {
			$ip       = $mm[0];
			$message  = $line;
			$level    = 'INFO'; // якщо формат не впізнано — вважаємо INFO
		} else {
			$message  = $line;
			$level    = 'INFO';
		}

		// ===== ФІЛЬТР РІВНІВ =====
		if (!empty($levels)) {
			$level_is_known = isset($known_map[$level]);
			$level_allowed  = isset($allow_map[$level]) || (!$level_is_known && $want_other);
			if (!$level_allowed) continue;
		}
		// ==========================

		// Маскування тільки для полів користувача та повідомлення в UI
		if ($sanitize_on) {
			$username_out = crit_sanitize_text($username);
			$message_out  = crit_sanitize_text($message);
		} else {
			$username_out = $username;
			$message_out  = $message;
		}
		if (!empty($ip)) {
			$ua_cache = get_transient('crit_ua_' . md5($ip));
		if (is_array($ua_cache) && !empty($ua_cache['bot'])) {
			$bot_label = strtolower((string)$ua_cache['bot']);
			// щоб не дублювати, якщо вже є "(bingbot)" тощо
        if (stripos($message_out, '(' . $bot_label . ')') === false) {
            $message_out .= ' (' . $bot_label . ')';
			}
		}
	}
		$style = '';
		if (!empty($ip)) {
			$style = crit_heat_style_from_count((int) ($ip_counts[$ip] ?? 0));
		}
		
		echo '<tr>';
		echo '<td style="font-family:monospace;">' . esc_html($time) . '</td>';
		echo '<td style="' . esc_attr($style) . '">' . esc_html($ip) . '</td>';
		echo '<td>' . esc_html($username_out) . '</td>';
		echo '<td><strong>' . esc_html($level) . '</strong></td>';
		echo '<td style="font-family:monospace; white-space:pre-wrap;">' . esc_html($message_out) . '</td>';
		echo '<td>';

		if ($ip) {
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
	if (! current_user_can('manage_options')) wp_send_json_error('Недостатньо прав', 403);
	check_ajax_referer('critical_logger_simple_nonce', 'nonce');

	$log_file = crit_log_file();
	if (! file_exists($log_file)) wp_send_json_error('Лог-файл не знайдено', 404);

	$limit  = isset($_POST['limit']) ? max(50, min(5000, intval($_POST['limit']))) : 500;
	$lines  = crit_tail_entries($log_file, $limit);
	wp_send_json_success(array_values($lines));
}

/* === AJAX: батч-гео та пул для списку IP === */
add_action('wp_ajax_critical_logger_geo_batch', 'critical_logger_geo_batch_cb');
function critical_logger_geo_batch_cb() {
	if (! current_user_can('manage_options')) wp_send_json_error('Недостатньо прав', 403);
	check_ajax_referer('critical_logger_simple_nonce', 'nonce');

	$ips = isset($_POST['ips']) ? (array) $_POST['ips'] : [];
	$ips = array_values(array_unique(array_map('sanitize_text_field', $ips)));
	$ips = array_filter($ips, static function($v){ return filter_var($v, FILTER_VALIDATE_IP); });
	$ips = array_slice($ips, 0, 100); // кап на 100

	$out = [];

	foreach ($ips as $ip) {
		$ip = sanitize_text_field($ip);
		if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;

		// пул (вже кешується всередині функцій)
		$pool_raw = function_exists('crit_get_ip_pool') ? crit_get_ip_pool($ip) : ['-'];
		if (!is_array($pool_raw)) $pool_raw = [$pool_raw];
		$pool = implode(', ', array_filter($pool_raw));

		// гео (кеш транзієнтом)
		// гео (кеш транзієнтом + fallback провайдер)
$geo_country = ''; $geo_city = '';
$cache_key = 'crit_geo_' . md5($ip);
$cached_geo = get_transient($cache_key);
if ($cached_geo !== false && is_array($cached_geo)) {
    $geo_country = $cached_geo['country'] ?? '';
    $geo_city    = $cached_geo['city'] ?? '';
} else {
    $providers = [
        [
            'url'         => "https://ipapi.co/{$ip}/json/",
            'country_key' => 'country_name',
            'city_key'    => 'city',
            'ok_check'    => null, // ipapi не має поля success
        ],
        [
            'url'         => "https://ipwho.is/{$ip}",
            'country_key' => 'country',
            'city_key'    => 'city',
            'ok_check'    => 'success', // ipwho.is має success=true/false
        ],
    ];

    foreach ($providers as $p) {
        $resp = wp_remote_get($p['url'], ['timeout' => 6]); // було 3 → стало 6
        if (is_wp_error($resp)) { continue; }

        $code = wp_remote_retrieve_response_code($resp);
        if ($code !== 200) { continue; }

        $data = json_decode(wp_remote_retrieve_body($resp), true);
        if (!is_array($data)) { continue; }

        if ($p['ok_check'] && (empty($data[$p['ok_check']]) || $data[$p['ok_check']] !== true)) {
            continue; // ipwho.is повернув success:false
        }

        $geo_country = trim((string)($data[$p['country_key']] ?? ''));
        $geo_city    = trim((string)($data[$p['city_key']] ?? ''));
        break;
    }

    // Поставимо кеш в будь-якому випадку:
    // - якщо вдалося витягти країну/місто → 24 год
    // - якщо ні (негативний кеш) → 30 хв, щоб не молотити сервіс щохвилини
    set_transient(
        $cache_key,
        ['country' => $geo_country, 'city' => $geo_city],
        ($geo_country || $geo_city) ? DAY_IN_SECONDS : 30 * MINUTE_IN_SECONDS
    );
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
});

if (!function_exists('crit_cidr_range_from_prefix')) {
	function crit_cidr_range_from_prefix($prefixIp, $length) {
		if (!filter_var($prefixIp, FILTER_VALIDATE_IP) || $length < 0 || $length > 32) return [null, null];
		$start = ip2long($prefixIp);
		if ($start === false) return [null, null];
		$mask = $length == 0 ? 0 : ((~0 << (32 - $length)) & 0xFFFFFFFF); // безпечно для PHP 7.2–8.3
		$network = $start & $mask;
		$broadcast = $network | (~$mask & 0xFFFFFFFF);
		return [long2ip($network), long2ip($broadcast)];
	}
}

/**
 * ======= Точне визначення пулу через RDAP (офіційні реєстри) =======
 * 1) Пробуємо ARIN RDAP і дозволяємо редірект до потрібного RIR
 * 2) Якщо ні — пробуємо напряму RIPE RDAP
 * 3) Повертаємо строго startAddress-endAddress
 */
/**
 * BGP-пул через Team Cymru (whois.cymru.com:43).
 * Повертає діапазон за анонсованим BGP-префіксом (start-end).
 * Кеш: 7 днів.
 */
function crit_get_ip_pool_via_cymru_bgp($ip) {
	$cache_key = 'crit_pool_bgp_' . md5($ip);
	$cached = get_transient($cache_key);
	if ($cached !== false) return $cached;

	if (!filter_var($ip, FILTER_VALIDATE_IP)) return '';

	$errno = 0; $errstr = '';
	$fp = fsockopen('whois.cymru.com', 43, $errno, $errstr, 6);
	if ($fp === false) {
	crit_log_internal("fsockopen whois.cymru.com failed: {$errno} {$errstr}");
	return '';
}

	stream_set_timeout($fp, 6);

	// " -v <ip>" — verbose одна лінія: AS | IP | BGP Prefix | CC | ...
	fwrite($fp, " -v " . $ip . "\n");
	$resp = '';
	while (!feof($fp)) {
		$line = fgets($fp, 4096);
		if ($line === false) break;
		$resp .= $line;
	}
	fclose($fp);
	if ($resp === '') return '';

	// Беремо перший CIDR типу a.b.c.d/n (це й буде "BGP Prefix")
	if (preg_match('/\b(\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2})\b/', $resp, $m)) {
		list($pfx, $len) = explode('/', $m[1], 2);
		if (!function_exists('crit_cidr_range_from_prefix')) {
			// safety: якщо хелпер ще не визначений
			function crit_cidr_range_from_prefix($prefixIp, $length) {
				if (!filter_var($prefixIp, FILTER_VALIDATE_IP) || $length < 0 || $length > 32) return [null, null];
				$start = ip2long($prefixIp);
				if ($start === false) return [null, null];
				$mask = $length == 0 ? 0 : ((~0 << (32 - $length)) & 0xFFFFFFFF);
				$network = $start & $mask;
				$broadcast = $network | (~$mask & 0xFFFFFFFF);
				return [long2ip($network), long2ip($broadcast)];
			}
		}
		[$s, $e] = crit_cidr_range_from_prefix($pfx, (int)$len);
		if ($s && $e) {
			$range = $s . '-' . $e;
			set_transient($cache_key, $range, 7 * DAY_IN_SECONDS);
			return $range;
		}
	}
	return '';
}

function crit_get_ip_pool_via_rdap($ip) {
	$cache_key = 'crit_pool_rdap_v2_' . md5($ip); // v2: знецінюємо старий кеш
	$cached = get_transient($cache_key);
	if ($cached !== false) return $cached;

	$url = "https://rdap.arin.net/registry/ip/" . rawurlencode($ip); // ARIN редіректить у потрібний RIR
	$max_hops = 5;
	$seen = [];
	$outer_range = '';

	for ($i = 0; $i < $max_hops; $i++) {
		$resp = wp_remote_get($url, [
			'timeout'	  => 12,
			'redirection'  => 5,
			'headers'	  => ['Accept' => 'application/rdap+json, application/json'],
		]);
		if (is_wp_error($resp)) break;
		$code = wp_remote_retrieve_response_code($resp);
		if ($code < 200 || $code >= 300) break;

		$data = json_decode(wp_remote_retrieve_body($resp), true);
		$is_v6 = (strpos($ip, ':') !== false);

		// 1) Якщо це IPv6 — спробуємо cidr0_cidrs.v6prefix
		if ($is_v6 && !empty($data['cidr0_cidrs']) && is_array($data['cidr0_cidrs'])) {
			foreach ($data['cidr0_cidrs'] as $cid) {
				if (!empty($cid['v6prefix']) && isset($cid['length'])) {
					$cidr = $cid['v6prefix'] . '/' . intval($cid['length']);
					set_transient($cache_key, $cidr, 7 * DAY_IN_SECONDS);
					return $cidr;
				}
			}
		}

		// 2) Якщо маємо start/end і це IPv6 — повертаємо як є (без обчислень span)
		$start = $data['startAddress'] ?? ($data['network']['startAddress'] ?? null);
		$end   = $data['endAddress']   ?? ($data['network']['endAddress']   ?? null);
		if ($is_v6 && $start && $end && strpos($start, ':') !== false) {
			$range = $start . '-' . $end;
			set_transient($cache_key, $range, 7 * DAY_IN_SECONDS);
			return $range;
		}
		if (!is_array($data)) break;

		// Збираємо кандидатні діапазони
		$ranges = [];

		// ARIN-специфічні cidr0_cidrs → перетворюємо у start-end
		if (!empty($data['cidr0_cidrs']) && is_array($data['cidr0_cidrs'])) {
			foreach ($data['cidr0_cidrs'] as $cid) {
				$pfx = $cid['v4prefix'] ?? '';
				$len = isset($cid['length']) ? intval($cid['length']) : null;
				if ($pfx && $len !== null) {
					[$s, $e] = crit_cidr_range_from_prefix($pfx, $len);
					if ($s && $e) $ranges[] = [$s, $e];
				}
			}
		}

		// Загальні RDAP-поля
		$start = $data['startAddress'] ?? ($data['network']['startAddress'] ?? null);
		$end   = $data['endAddress']   ?? ($data['network']['endAddress']   ?? null);
		if ($start && $end) $ranges[] = [$start, $end];

		// Обираємо НАЙШИРШИЙ із наявних на цьому вузлі
		if ($ranges) {
			$best = null; $best_span = -1;
			foreach ($ranges as $r) {
				if (!filter_var($r[0], FILTER_VALIDATE_IP) || !filter_var($r[1], FILTER_VALIDATE_IP)) continue;
				$s = (float) sprintf('%u', ip2long($r[0]));
				$e = (float) sprintf('%u', ip2long($r[1]));
				$span = $e - $s;
				if ($span > $best_span) { $best_span = $span; $best = $r; }
			}
			if ($best) $outer_range = $best[0] . '-' . $best[1];
		}

		// Йдемо догори, якщо є батьківський об'єкт
		$up = '';
		if (!empty($data['links']) && is_array($data['links'])) {
			foreach ($data['links'] as $lnk) {
				if (!empty($lnk['rel']) && strtolower($lnk['rel']) === 'up' && !empty($lnk['href'])) {
					$up = $lnk['href'];
					break;
				}
			}
		}
		if (!$up || isset($seen[$up])) break;
		$seen[$up] = true;
		$url = $up;
	}

	if ($outer_range) {
		set_transient($cache_key, $outer_range, 7 * DAY_IN_SECONDS);
		return $outer_range;
	}
	return '';
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
	$cache_key = 'crit_pool_ripe_precise_v2_' . md5($ip);
	$cached = get_transient($cache_key);
	if ($cached !== false) return $cached;

	$url = 'https://rest.db.ripe.net/search.json?query-string=' . urlencode($ip) . '&type-filter=inetnum';
	$resp = wp_remote_get($url, ['timeout' => 10]);
	if (is_wp_error($resp)) return '';

	$body = wp_remote_retrieve_body($resp);
	$data = json_decode($body, true);
	if (empty($data['objects']['object'])) return '';

	$target = sprintf('%u', ip2long($ip));
	$best_start = null; $best_end = null; $best_span = -1;

	foreach ($data['objects']['object'] as $obj) {
		foreach ($obj['attributes']['attribute'] ?? [] as $attr) {
			if (strtolower($attr['name'] ?? '') !== 'inetnum') continue;
			if (!preg_match('/^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$/', trim($attr['value']), $m)) continue;

			$start = sprintf('%u', ip2long($m[1]));
			$end   = sprintf('%u', ip2long($m[2]));
			if ($start <= $target && $target <= $end) {
				$span = $end - $start;
				if ($span > $best_span) { $best_span = $span; $best_start = $start; $best_end = $end; }
			}
		}
	}

	if ($best_span >= 0) {
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
	
	// 0) BGP-префікс — найпридатніший для "пулу" в інтерфейсі
	$bgp = crit_get_ip_pool_via_cymru_bgp($ip);
	if (!empty($bgp)) return [$bgp];

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
	$total   = 0;
	foreach ($cidr_list as $cidr) {
		$chunk = [];
		if (strpos($cidr, '-') !== false) {
			list($start_ip, $end_ip) = explode('-', $cidr);
			$chunk = crit_ip_range_to_ips(trim($start_ip), trim($end_ip));
		} elseif (strpos($cidr, '/') !== false) {
			$chunk = crit_cidr_to_ips($cidr);
		} else {
			$chunk = [$cidr];
		}

		$total += is_array($chunk) ? count($chunk) : 1;
		if ($total > CRIT_IP_EXPAND_MAX) {
			// обрубуємо: повертаємо як є, без подальшого розширення
			$all_ips[] = is_array($chunk) ? (reset($chunk) . ' … (truncated)') : $chunk;
			break;
		}

		$all_ips = array_merge($all_ips, $chunk);
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
	$end   = ip2long($end_ip);
	if ($start === false || $end === false || $start > $end) return [];
	$count = ($end - $start + 1);
	if ($count > CRIT_IP_EXPAND_MAX) {
		// занадто велика множина — повертаємо як діапазон без розгортання
		return [ long2ip($start) . '-' . long2ip($end) ];
	}
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

	if (!defined('CRIT_ALLOW_SHELL_WHOIS') || !CRIT_ALLOW_SHELL_WHOIS) {
		return '';
	}

	// Базові перевірки середовища
	if (!function_exists('shell_exec')) {
		return '';
	}
	$disabled = ini_get('disable_functions');
	if ($disabled && stripos($disabled, 'shell_exec') !== false) {
		return '';
	}

	// Додаткові обмеження/allowlist
	$bin = defined('CRIT_WHOIS_BIN') && CRIT_WHOIS_BIN ? CRIT_WHOIS_BIN : 'whois';
	if (!filter_var($ip, FILTER_VALIDATE_IP)) {
		return '';
	}

	$cmd = $bin . ' ' . escapeshellarg($ip) . ' 2>&1';
	$output = shell_exec($cmd);
	if (!is_string($output) || $output === '') {
		return '';
	}

	// Захист від «нескінченності»: обрізаємо до ~200KB
	if (strlen($output) > 200000) {
		$output = substr($output, 0, 200000);
	}

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
	$log_file = crit_log_file();
	if (!file_exists($log_file)) return;

	$raw = file_get_contents($log_file);
	if ($raw === false) $raw = '';

	$entries = crit_split_log_entries($raw);
	if (!$entries) return;

	$now = time();
	$limit_ts = $now - ($days * DAY_IN_SECONDS);

	$tz = function_exists('wp_timezone') ? wp_timezone() : new DateTimeZone('UTC');
	$kept = [];

	foreach ($entries as $ln) {
		if (preg_match('/^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]/', $ln, $m)) {
			$dt = DateTimeImmutable::createFromFormat('Y-m-d H:i:s', $m[1], $tz);
			$ts = $dt ? $dt->getTimestamp() : false;
			if ($ts !== false && $ts >= $limit_ts) {
				$kept[] = $ln;
			}
		} else {
			$kept[] = $ln; // незрозумілий формат — не чіпаємо
		}
	}

	$out = implode("\n", $kept);
	if ($out !== '') $out .= "\n";
	@file_put_contents($log_file, $out, LOCK_EX);
}
/* Виконуємо очищення/експорт/очистку тільки при вході в сторінку */
add_action('admin_init', function() {
	if (isset($_GET['page']) && $_GET['page'] === 'critical-event-logs') {
		critical_logger_cleanup_old_logs(30);

		// Очистити лог
		if (
			isset($_POST['clear_log']) &&
			current_user_can('manage_options') &&
			check_admin_referer('clear_log_action', 'clear_log_nonce')
		) {
			$log_file = crit_log_file();
			file_put_contents($log_file, '', LOCK_EX);
			wp_safe_redirect(add_query_arg('cleared', '1', menu_page_url('critical-event-logs', false)));
			exit;
		}

		// (за бажанням) тут може бути Експорт CSV — якщо треба, став потоком як ми обговорювали
	}
});
/**
 * Порахує кількість лог-записів у файлі, читаючи його порціями.
 * Розпізнає записи за префіксом таймстемпа: [YYYY-MM-DD HH:MM:SS]
 */
function crit_count_entries_in_file(string $file, int $chunkSize = 131072): int {
	if (!is_file($file)) return 0;
	$fp = @fopen($file, 'rb');
	if (!$fp) return 0;

	$re  = '/\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]/';
	$buf = '';
	$cnt = 0;

	while (!feof($fp)) {
		$buf .= fread($fp, $chunkSize) ?: '';
		$tailKeep = 64;
		if (strlen($buf) > $chunkSize * 2) {
			$scan = substr($buf, 0, -$tailKeep);
			preg_match_all($re, $scan, $m);
			$cnt += count($m[0]);
			$buf = substr($buf, -$tailKeep);
		}
	}
	preg_match_all($re, $buf, $m2);
	$cnt += count($m2[0]);

	fclose($fp);
	return $cnt;
}

/* Головна адмін-сторінка для перегляду логів */
function critical_logger_admin_page() {
	ob_start();
// Збереження налаштування "Санітувати PII"
if (
	isset($_POST['crit_privacy_save']) &&
	current_user_can('manage_options') &&
	check_admin_referer('crit_privacy_save', 'crit_privacy_nonce')
) {
	update_option('crit_log_sanitize', isset($_POST['crit_log_sanitize']) ? '1' : '0');
	echo '<div class="notice notice-success"><p>Налаштування приватності збережено.</p></div>';
}

	$log_file = crit_log_file();
	// --- Очистити кеш пул/гео ---
if (
	isset($_POST['clear_ipcache']) &&
	current_user_can('manage_options') &&
	check_admin_referer('critical_logger_clear_ipcache_action', 'critical_logger_clear_ipcache_nonce')
) {
	global $wpdb;

	// Патерни наших кеш-ключів (звичайні transients)
	$like_patterns = array(
		'crit_geo_%',
		'crit_pool_%',
		'crit_pool_bgp_%',
		'crit_pool_rdap_v2_%',
		'crit_pool_ripe_precise_v2_%',
		'crit_pool_ripewhois_%'
	);

	foreach ($like_patterns as $pat) {
		// видаляємо transient-и (НЕ site_transient)
		$rows = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
				'_transient_' . $pat
			)
		);
		foreach ($rows as $opt_name) {
			$key = substr($opt_name, strlen('_transient_'));
			delete_transient($key);
		}
		// видаляємо timeouts
		$rows = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
				'_transient_timeout_' . $pat
			)
		);
		foreach ($rows as $opt_name) {
			delete_option($opt_name);
		}
	}

	// (опційно) multisite: чистимо site_transient*
	if (is_multisite()) {
		$sitemeta = $wpdb->sitemeta;
		$site_id  = get_current_network_id();

		foreach ($like_patterns as $pat) {
			// ключі site_transient
			$meta_keys = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT meta_key FROM {$sitemeta} WHERE site_id=%d AND meta_key LIKE %s",
					$site_id,
					'_site_transient_' . $pat
				)
			);
			foreach ($meta_keys as $mk) {
				$key = substr($mk, strlen('_site_transient_'));
				delete_site_transient($key);
			}
			// таймаути
			$meta_keys = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT meta_key FROM {$sitemeta} WHERE site_id=%d AND meta_key LIKE %s",
					$site_id,
					'_site_transient_timeout_' . $pat
				)
			);
			foreach ($meta_keys as $mk) {
				delete_site_option($mk);
			}
		}
	}

	echo '<div class="notice notice-success"><p>Кеш пулу/гео очищено.</p></div>';
}

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
						$entry = '[' . crit_log_time() . '][System][admin][INFO] Заблоковано вручну: ' . $entry_ip;
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
	echo '<div class="crit-admin-header" style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:8px;">';
	echo '<h1 style="margin:0;">Critical Event Logger</h1>';
	echo '<button id="crit-info-open" type="button" class="button button-secondary" aria-haspopup="dialog" aria-expanded="false" aria-controls="crit-info-modal">Info</button>';
	echo '</div>';
// === INFO MODAL ===
?>
<style id="crit-info-modal-css">
	#crit-info-modal[hidden]{display:none;}
	#crit-info-modal{position:fixed;inset:0;z-index:100000;}
	#crit-info-modal .crit-modal__backdrop{position:absolute;inset:0;background:rgba(0,0,0,.35);}
	#crit-info-modal .crit-modal__dialog{
		position:relative;max-width:780px;margin:6vh auto;background:#fff;border-radius:8px;
		box-shadow:0 10px 30px rgba(0,0,0,.2);padding:20px 22px;outline:0;
	}
	#crit-info-modal h2{margin:0 32px 10px 0;}
	#crit-info-modal .crit-modal__body{line-height:1.55;max-height:65vh;overflow:auto;padding-right:2px;}
	#crit-info-modal .crit-modal__close{
		position:absolute;right:12px;top:10px;border:0;background:transparent;font-size:22px;line-height:1;cursor:pointer;
	}
	#crit-info-modal .crit-kbd{display:inline-block;border:1px solid #ddd;border-bottom-width:2px;border-radius:4px;padding:0 5px;font:12px/20px monospace;background:#f8f8f8}
	#crit-info-modal ul{margin:0 0 10px 18px}
	#crit-info-modal li{margin:6px 0}
	#crit-info-modal code{background:#f6f7f7;border:1px solid #e2e4e7;border-radius:3px;padding:1px 4px}
</style>
<div id="crit-info-modal" role="dialog" aria-modal="true" aria-labelledby="crit-info-title" hidden>
	<div class="crit-modal__backdrop" data-close="1"></div>
	<div class="crit-modal__dialog" role="document" tabindex="-1">
		<button type="button" class="crit-modal__close" id="crit-info-close" aria-label="Закрити" title="Закрити (Esc)">×</button>
		<h2 id="crit-info-title">Що вміє Critical Event Logger</h2>
		<div class="crit-modal__body">
			<p><strong>Огляд функцій інтерфейсу цієї сторінки:</strong></p>
			<ul>
				<li><strong>Таблиця логів</strong> — AJAX-перегляд останніх записів із підсвіченням частих IP. Фільтруй за рівнями зверху блоку «Показувати рівні».</li>
				<li><strong>Виявлені IP</strong> — зведена таблиця частоти появи IP. Для кожного IP асинхронно визначається <em>пул</em> (BGP/RDAP/RIPE) і <em>гео</em>.</li>
				<li><strong>Кнопки дій</strong>:
					<ul>
						<li><em>Оновити</em> — перезавантажує таблицю логів, список IP і лічильник записів.</li>
						<li><em>Очистити лог</em> — повністю очищає файл <code>.../uploads/critical-event-logger/logs/events.log</code>.</li>
						<li><em>Очистити кеш пул</em> — скидає кеш RDAP/BGP/гео (корисно, коли пул/гео змінилися у провайдера).</li>
					</ul>
				</li>
				<li><strong>Блокування</strong>:
					<ul>
						<li><em>Блокувати</em> поруч із записом/IP — додає правило до <code>.htaccess</code> (враховується Apache 2.2/2.4). Якщо <code>.htaccess</code> недоступний — запис у <code>blocked_ips.txt</code>.</li>
						<li><em>Блокувати пул</em> — після визначення пулу кнопка активується й підставляє отриманий діапазон/CIDR.</li>
						<li><em>Заблокувати IP вручну</em> — приймає одиночний IP, CIDR (напр. <code>178.128.16.0/20</code>) або діапазон <code>start - end</code>. Діапазони автоматично конвертуються у мінімальний набір CIDR.</li>
					</ul>
				</li>
				<li><strong>Лічильник записів</strong> — швидкий підрахунок загальної кількості лог-записів.</li>
				<li><strong>Ротація</strong> — під час відкриття сторінки видаляються записи старші 30 днів (див. <code>critical_logger_cleanup_old_logs()</code> та <code>rotation.php</code>).</li>
			</ul>

			<h3 style="margin-top:14px;">Рівні подій (що і чим позначається)</h3>
			<ul>
				<li><strong>INFO</strong> — звичайні дії: успішний вхід/вихід; реєстрація; оновлення профілю/ролі; створення/оновлення записів; створення/зміни коментарів; додавання медіа; оновлення меню; збереження кастомайзера; успішне відправлення CF7; оновлення опцій (не-секрети); службові події апдейтера, що не є власне <code>update</code>.</li>

				<li><strong>NOTICE</strong> — помітні, але очікувані речі: поодинокі помилки входу; запит/зміна пароля; активація/деактивація плагінів; зміна теми; завершення автооновлень; події апдейтера з <code>action=update</code>; оновлення опцій із маскуванням секретів (<code>pass|secret|key|token|salt</code>); REST 4xx (окрім 404); «звичайні» 404 без ознак сканування; виклики XML-RPC методів.</li>

				<li><strong>WARNING</strong> — потенційний ризик: ≥3 помилки входу з одного IP за 10 хв; видалення користувача/запису/медіа; надання/відкликання супер-адміна в мультисайті; позначення коментаря як спам; редагування файлів у адмінці через AJAX; WooCommerce low stock.</li>

				<li><strong>ERROR</strong> — збої: помилки відправлення пошти (<code>wp_mail_failed</code>); CF7 mail failed; помилки логіну через XML-RPC; REST 5xx.</li>

				<li><strong>FATAL</strong> — фатальні PHP-помилки (падіння процесу): <code>E_ERROR</code>, <code>E_PARSE</code>, <code>E_CORE_ERROR</code>, <code>E_COMPILE_ERROR</code> тощо (перехоплюються обробниками плагіна).</li>

				<li><strong>DEPRECATED</strong> — застарілі виклики/попередження: <code>E_DEPRECATED</code>, <code>E_USER_DEPRECATED</code> (можливий <code>E_STRICT</code>), діагностика для оновлення коду.</li>

				<li><strong>SCAN</strong> — явні ознаки сканування/атак: ≥6 помилок входу з одного IP за 10 хв; REST 404; «підозрілі» 404 (звернення до <code>.php</code>/<code>.php.suspected</code>, PHP у <code>/wp-content/plugins|themes/</code>, довгі токени на <code>.html</code> тощо).</li>
			</ul>
			<p style="margin:8px 0 12px; color:#444;">
				<strong>Ескалація брутфорсу:</strong> 1–2 спроби → <code>NOTICE</code>, 3–5 → <code>WARNING</code>, 6+ → <code>SCAN</code> (вікно <code>CRIT_BRUTEFAIL_WINDOW=600</code> c).
			</p>

			<p><strong>Джерела даних:</strong> пул через Team&nbsp;Cymru (BGP), RDAP (офіційні RIR), RIPE; гео — <code>ipapi.co</code> / <code>ipwho.is</code> з кешуванням.</p>
			<p><span class="crit-kbd">Esc</span> — закрити модалку. Клік поза вікном — теж закриє.</p>
		</div>
	</div>
</div>

<?php

	if (! file_exists($log_file)) {
		echo '<div class="notice notice-error"><p>Файл логів не знайдено: ' . esc_html($log_file) . '</p></div></div>';
		if (ob_get_level()) ob_end_flush();
		return;
	}

	$total_logs = crit_count_entries_in_file($log_file);

	echo '<p>Всього записів: <strong id="crit-total-count">' . esc_html($total_logs) . '</strong></p>';

	// Кнопки дій
	echo '<div style="margin-bottom:12px;">';
	echo '<button id="crit-reload-logs" type="button" class="button">Оновити</button> ';
	// 1) Очистити лог (як і було)
	echo '<form method="post" style="display:inline; margin-left:8px;">'
		. wp_nonce_field('critical_logger_clear_logs_action', 'critical_logger_clear_logs_nonce', true, false)
		. '<input type="hidden" name="clear_logs" value="1">'
		. '<input type="submit" class="button button-secondary" value="Очистити лог" onclick="return confirm(\'Очистити лог? Це незворотно.\');">'
		. '</form>';
	// 2) Очистити кеш пул (НОВА КНОПКА)
	echo '<form method="post" style="display:inline; margin-left:8px;">'
		. wp_nonce_field('critical_logger_clear_ipcache_action', 'critical_logger_clear_ipcache_nonce', true, false)
		. '<input type="hidden" name="clear_ipcache" value="1">'
		. '<input type="submit" class="button" value="Очистити кеш пул" onclick="return confirm(\'Очистити кеш пул?\');">'
		. '</form>';
	echo '</div>';
	$sanitize_current = get_option('crit_log_sanitize', '0') === '1';

	

	// --- Фільтр рівнів лога (UI) ---
	echo '<div id="crit-level-filters" style="margin:10px 0 12px; padding:8px; border:1px solid #ddd; border-radius:6px; background:#fff;">';
	echo '<strong>Показувати рівні:</strong> ';
	$levels_ui = ['INFO','WARNING','ERROR','NOTICE','FATAL','DEPRECATED','SCAN'];
	foreach ($levels_ui as $lvl) {
	echo '<label style="margin-right:10px;"><input type="checkbox" class="crit-lvl" value="' . esc_attr($lvl) . '" checked> ' . esc_html($lvl) . '</label>';
	}
	echo '<label style="margin-left:8px;"><input type="checkbox" class="crit-lvl" value="__OTHER__" checked> Інше</label>';
	echo '<span style="margin-left:10px;">';
	echo '<a href="#" id="crit-level-all">все</a> · <a href="#" id="crit-level-none">жодного</a>';
	echo '</span>';
	echo '<div style="color:#666; margin-top:6px; font-size:12px;">Порада: “Інше” — це рідкісні системні рівні (PARSE ERROR, STRICT, CORE WARNING тощо).</div>';
	echo '</div>';

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
	
	echo '<div style="margin:12px 0; padding:10px; border:1px solid #ddd; background:#fff; border-radius:6px;">';
	echo '<h3 style="margin-top:0;">Приватність логів</h3>';
	echo '<form method="post" style="margin:0;">';
	wp_nonce_field('crit_privacy_save', 'crit_privacy_nonce');
	echo '<label><input type="checkbox" name="crit_log_sanitize" value="1" '.checked(true, $sanitize_current, false).'> ';
	echo '🛡️ Санітувати PII (email/IP/телефон) у записах журналу';
	echo '</label>';
	echo '<p class="description" style="margin:.5em 0 0; color:#666;">При ввімкненні особисті ідентифікатори у нових рядках лога будуть замінюватися на маски.</p>';
	echo '<p style="margin-top:10px;"><button type="submit" name="crit_privacy_save" class="button button-primary">Зберегти</button></p>';
	echo '</form>';
	echo '</div>';
	?>
<script>
(function($){
// === INFO MODAL JS ===
(function(){
	var $modal   = jQuery('#crit-info-modal');
	var $dialog  = $modal.find('.crit-modal__dialog');
	var $openBtn = jQuery('#crit-info-open');
	var $closeBtn= jQuery('#crit-info-close');
	var lastFocus = null;

	function openModal(){
		lastFocus = document.activeElement;
		$modal.removeAttr('hidden');
		$openBtn.attr('aria-expanded','true');
		// фокус у діалог
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
		if (jQuery(e.target).is('[data-close], .crit-modal__backdrop')) { closeModal(); }
	});
	jQuery(document).on('keydown', function(e){
		if (e.key === 'Escape' && !$modal.is('[hidden]')) { e.preventDefault(); closeModal(); }
	});
})();
	

// --- збирання вибраних рівнів з чекбоксів ---
function critGetSelectedLevels(){
	var arr = [];
	jQuery('input.crit-lvl:checked').each(function(){
		arr.push(this.value);
	});
	return arr;
}
// 0) ЛІЧИЛЬНИК — повертаємо jqXHR
window.critFetchTotalCount = function(){
	return jQuery.post(ajaxurl, {
		action: 'critical_logger_total_count',
		nonce: '<?php echo wp_create_nonce("critical_logger_simple_nonce"); ?>'
	}).done(function(resp){
		if (resp && resp.success && resp.data && typeof resp.data.count !== 'undefined') {
			jQuery('#crit-total-count').text(resp.data.count);
		}
	});
};

// 1) ЛОГ — повертаємо jqXHR
window.critFetchLogTable = function(limit){
	return $.post(ajaxurl, {
		action: 'critical_logger_log_table',
		nonce: '<?php echo wp_create_nonce("critical_logger_simple_nonce"); ?>',
		limit: limit || 500,
		levels: critGetSelectedLevels() // ← ПЕРЕДАЄМО фільтри
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
ips = ips.slice(0, 100);
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
	return jQuery.when(
		window.critFetchLogTable(500),
		window.critFetchDetectedIPs(),
		window.critFetchTotalCount() // ← додали
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
// Переключення чекбоксів → миттєве перезавантаження таблиці лога
$(document).on('change', 'input.crit-lvl', function(){
	window.critFetchLogTable(500);
	window.critFetchTotalCount();
});

// Лінки "все/жодного"
$('#crit-level-all').on('click', function(e){
	e.preventDefault();
	$('input.crit-lvl').prop('checked', true);
	window.critFetchLogTable(500);
});
$('#crit-level-none').on('click', function(e){
	e.preventDefault();
	$('input.crit-lvl').prop('checked', false);
	// якщо все знято — покажемо порожньо; або ввімкнути INFO за замовч.
	window.critFetchLogTable(500);
});

})(jQuery);
</script>

	<?php

	if (ob_get_level()) ob_end_flush();
}
// При деактивації — прибираємо крон завдання ротації
register_deactivation_hook(__FILE__, function(){
	wp_clear_scheduled_hook('crit_daily_log_rotation');
});


// Підключення intel аналізу
if (file_exists(plugin_dir_path(__FILE__) . 'intel-admin.php')) {
	require_once plugin_dir_path(__FILE__) . 'intel-admin.php';
}
// Підключення AT налітики
if (file_exists(plugin_dir_path(__FILE__) . 'ai.php')) {
	require_once plugin_dir_path(__FILE__) . 'ai.php';
}
// Підключення GeoBlock
if (file_exists(plugin_dir_path(__FILE__) . 'geoblock.php')) {
	require_once plugin_dir_path(__FILE__) . 'geoblock.php';
}
// === Ротація логів (автоочищення та архівація) ===
if (file_exists(plugin_dir_path(__FILE__) . 'rotation.php')) {
	require_once plugin_dir_path(__FILE__) . 'rotation.php';
}
// Settings page (API keys)
if (file_exists(plugin_dir_path(__FILE__) . 'seting.php')) {
	require_once plugin_dir_path(__FILE__) . 'seting.php';
}
if (file_exists(plugin_dir_path(__FILE__) . 'htaccess-blocklist.php')) {
	require_once plugin_dir_path(__FILE__) . 'htaccess-blocklist.php';
}