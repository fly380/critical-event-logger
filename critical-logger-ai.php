<?php
/**
 * Critical Event Logger — helper module
 * Copyright © 2025 Казмірчук Андрій
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if (!defined('ABSPATH')) exit;

// --- допоміжні ---
// 1) Розрізати файл на окремі записи навіть без \n між ними
if (!function_exists('crit_split_log_entries')) {
	function crit_split_log_entries(string $raw): array {
		$raw = trim($raw);
		if ($raw === '') return [];
		$parts = preg_split('/(?=\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\])/', $raw);
		return array_values(array_filter(array_map('trim', $parts), static function($s){ return $s !== ''; }));
	}
}

// 2) Парс одного запису у структуру
function crit_ai_parse_line(string $line): array {
	// Формат: [time][ip|tag][user?][LEVEL] message
	$time = $ip = $user = $level = $msg = $tag = '';
	if (preg_match('/^\[([0-9\- :]+)\]\[([^\]]+)\]\[([^\]]*)\]\[([^\]]+)\]\s?(.*)$/u', $line, $m)) {
		$time  = $m[1];     // 2025-10-18 11:20:13
		$iptag = trim($m[2]);
		$user  = trim($m[3]);
		$level = trim($m[4]);
		$msg   = $m[5];

		// Якщо друге поле схоже на IP — це IP, інакше це tag (типу GeoBlock)
		if (filter_var($iptag, FILTER_VALIDATE_IP)) {
			$ip = $iptag;
		} else {
			$tag = $iptag; // напр. GeoBlock
			// спробуємо зняти IP з message у дужках
			if (preg_match('/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', $msg, $mm)) {
				$ip = $mm[1];
			}
		}
	} else {
		// fallback: спробуємо витягти хоча б IP і вважати все message
		if (preg_match('/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', $line, $mm)) $ip = $mm[1];
		$msg = $line;
	}
	return [
		'time'  => $time,
		'ip'    => $ip,
		'user'  => $user,
		'level' => strtoupper($level),
		'tag'   => $tag,
		'msg'   => $msg,
	];
}

// 3) Топ N за лічильником (асоціативний масив value=>count)
function crit_ai_topN(array $counts, int $n = 10): array {
	arsort($counts);
	return array_slice($counts, 0, $n, true);
}

/**
 * Зчитує лог-файл та готує аналітику
 */
function crit_ai_generate_insights($limit = 300) {
	$log_file = plugin_dir_path(__FILE__) . 'logs/events.log';
	if (!file_exists($log_file)) {
		return [
			'risk' => [
				'code'    => 'unknown',
				'label'   => '⚠️ Логів не знайдено',
				'reasons' => ['Файл logs/events.log відсутній або порожній.'],
			],
			'stats'   => [],
			'raw'     => [],
			'details' => []
		];
	}

	// читаємо “сирі” дані та ріжемо на записи
	$raw = @file_get_contents($log_file) ?: '';
	$entries = crit_split_log_entries($raw);
	if (!$entries) {
		return [
			'risk' => [
				'code'    => 'unknown',
				'label'   => '⚠️ Порожній лог',
				'reasons' => ['Вміст файлу відсутній.'],
			],
			'stats'   => [],
			'raw'     => [],
			'details' => []
		];
	}

	// беремо тільки останні $limit записів для швидкості
	$entries = array_slice($entries, -$limit);

	// лічильники/збірники
	$stats = [
		'total'    => count($entries),
		'errors'   => 0,
		'warnings' => 0,
		'security' => 0,
		'geoblock' => 0,
		'logins'   => 0,
		'last24'   => [
			'errors'   => 0,
			'warnings' => 0,
			'security' => 0,
			'geoblock' => 0,
			'logins'   => 0,
			'total'    => 0,
		],
	];

	$now     = time();
	$dayAgo  = $now - DAY_IN_SECONDS;

	$cnt_ip = [];       // IP => count
	$cnt_user = [];     // user => count
	$cnt_country = [];  // country code (з GeoBlock-повідомлень)
	$cnt_level = [];    // INFO/WARN/ERROR/SECURITY => count
	$cnt_messages = []; // нормалізовані тексти => count
	$hours_hist = [];   // 'YYYY-MM-DD HH' => count

	$last_errors   = [];   // останні 5 ERROR
	$last_security = [];   // останні 5 SECURITY/WARN з тегом GeoBlock/безпеки
	$unique_ips = [];

	foreach ($entries as $line) {
		$rec = crit_ai_parse_line($line);

		// часові поля
		$is_last24 = false;
		if ($rec['time']) {
			$ts = strtotime($rec['time']);
			if ($ts !== false && $ts >= $dayAgo) {
				$is_last24 = true;
				$stats['last24']['total']++;
			}
			$hourKey = $ts ? date('Y-m-d H', $ts) : '';
			if ($hourKey) $hours_hist[$hourKey] = ($hours_hist[$hourKey] ?? 0) + 1;
		}

		// рівні/мітки
		$level = $rec['level'];
		if ($level) $cnt_level[$level] = ($cnt_level[$level] ?? 0) + 1;

		// категорії
		$has_error   = ($level === 'ERROR');
		$has_warning = ($level === 'WARN' || $level === 'WARNING');
		$has_sec     = ($level === 'SECURITY');
		$has_geo     = (strcasecmp($rec['tag'], 'GeoBlock') === 0) || stripos($rec['msg'], 'GeoBlock') !== false;
		$has_login   = (stripos($rec['msg'], 'login') !== false || stripos($rec['msg'], 'автентиф') !== false || stripos($rec['msg'], 'вхід') !== false);

		if ($has_error) { $stats['errors']++; if ($is_last24) $stats['last24']['errors']++; }
		if ($has_warning) { $stats['warnings']++; if ($is_last24) $stats['last24']['warnings']++; }
		if ($has_sec) { $stats['security']++; if ($is_last24) $stats['last24']['security']++; }
		if ($has_geo) { $stats['geoblock']++; if ($is_last24) $stats['last24']['geoblock']++; }
		if ($has_login){ $stats['logins']++; if ($is_last24) $stats['last24']['logins']++; }

		// IP/користувачі
		if ($rec['ip']) {
			$unique_ips[$rec['ip']] = true;
			$cnt_ip[$rec['ip']] = ($cnt_ip[$rec['ip']] ?? 0) + 1;
		}
		if ($rec['user']) {
			$u = trim($rec['user']) ?: 'guest';
			$cnt_user[$u] = ($cnt_user[$u] ?? 0) + 1;
		}

		// країна із повідомлень GeoBlock
		if ($has_geo && preg_match('/\b([A-Z]{2})\b/', $rec['msg'], $gm)) {
			$cc = $gm[1];
			$cnt_country[$cc] = ($cnt_country[$cc] ?? 0) + 1;
		}

		// нормалізуємо повідомлення для топів (забираємо IP/емейли/цифри, щоб схожі групувалися)
		$norm = preg_replace([
			'/\b\d{1,3}(?:\.\d{1,3}){3}\b/', // IP
			'/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i', // email
			'/\d+/' // числа
		], ['<ip>', '<email>', '<n>'], mb_strtolower($rec['msg']));
		$norm = trim($norm);
		if ($norm !== '') $cnt_messages[$norm] = ($cnt_messages[$norm] ?? 0) + 1;

		// колекції прикладів
		if ($has_error && count($last_errors) < 5) $last_errors[] = $line;
		if (($has_sec || $has_geo) && count($last_security) < 5) $last_security[] = $line;
	}

	// Топи
	$top_ip       = crit_ai_topN($cnt_ip, 10);
	$top_users    = crit_ai_topN($cnt_user, 10);
	$top_countries= crit_ai_topN($cnt_country, 10);
	$top_levels   = crit_ai_topN($cnt_level, 10);
	$top_messages = crit_ai_topN($cnt_messages, 10);

	// Прості аномалії
	$anomalies = [];
	$uniq_ip_count = count($unique_ips);
	if ($stats['security'] > 20) $anomalies[] = "Висока кількість подій безпеки: {$stats['security']} (порог >20)";
	if ($stats['errors'] > 10)   $anomalies[] = "Багато помилок: {$stats['errors']} (порог >10)";
	if (!empty($top_ip)) {
		$firstIp = array_key_first($top_ip);
		if ($top_ip[$firstIp] >= max(5, (int)ceil($stats['total'] * 0.1))) {
			$anomalies[] = "IP {$firstIp} з’являється дуже часто: {$top_ip[$firstIp]} раз(ів)";
		}
	}
	// пікові години
	if (!empty($hours_hist)) {
		arsort($hours_hist);
		$bigHour = array_key_first($hours_hist);
		if ($hours_hist[$bigHour] >= max(10, (int)ceil($stats['total'] * 0.2))) {
			$anomalies[] = "Сплеск подій у годину {$bigHour}: {$hours_hist[$bigHour]} записів";
		}
	}

	// Ризик/пояснення
	$reasons = [];
	$risk_code  = 'green';
	$risk_label = '🟢 Стабільно';

	if ($stats['warnings'] > 10)  $reasons[] = "Попереджень: {$stats['warnings']} (>10)";
	if ($stats['security'] > 5)   $reasons[] = "Подій безпеки: {$stats['security']} (>5)";
	if ($stats['last24']['security'] > 0) $reasons[] = "Є події безпеки за 24 год: {$stats['last24']['security']}";
	if ($stats['geoblock'] > 0)   $reasons[] = "Блокувань GeoBlock: {$stats['geoblock']}";

	$danger_reasons = [];
	if ($stats['errors'] > 10)     $danger_reasons[] = "Помилок: {$stats['errors']} (>10)";
	if ($stats['security'] > 20)   $danger_reasons[] = "Подій безпеки: {$stats['security']} (>20)";

	if (!empty($danger_reasons)) {
		$risk_code  = 'red';
		$risk_label = '🔴 Небезпечно';
		$reasons = array_merge($danger_reasons, $reasons);
	} elseif (!empty($reasons)) {
		$risk_code  = 'amber';
		$risk_label = '🟠 Попередження';
	}
	$reasons = array_merge($reasons, $anomalies);

	return [
		'risk' => [
			'code'    => $risk_code,
			'label'   => $risk_label,
			'reasons' => $reasons ?: ['В аномаліях не помічено перевищення порогів.'],
		],
		'stats' => array_merge($stats, [
			'unique_ips' => $uniq_ip_count,
		]),
		// останні 100 сирих рядків (для AI/перегляду)
		'raw' => array_slice($entries, -100),
		// деталі для відображення
		'details' => [
			'top_ip'        => $top_ip,
			'top_users'     => $top_users,
			'top_countries' => $top_countries,
			'top_levels'    => $top_levels,
			'top_messages'  => $top_messages,
			'hours_hist'    => $hours_hist,
			'last_errors'   => $last_errors,
			'last_security' => $last_security,
		],
	];
}

/** Повертає шлях до WP CA bundle або null */
function crit_guess_wp_cafile() {
	$cafile = ABSPATH . WPINC . '/certificates/ca-bundle.crt';
	return file_exists($cafile) ? $cafile : null;
}

/**
 * Генерує аналітичний звіт через OpenAI API з 3 рівнями fallback і діагностикою
 */
function crit_ai_analyze_logs_with_openai($lines) {
	if (!defined('CRIT_OPENAI_KEY') || empty(CRIT_OPENAI_KEY)) {
		return '⚠️ Відсутній API-ключ OpenAI (CRIT_OPENAI_KEY). Додай його у wp-config.php';
	}

	$prompt = "Ти — аналітик безпеки WordPress. Проаналізуй уривки журналів подій і дай короткий, чіткий звіт українською:\n"
		. "1) Домінуючі типи подій (помилки, безпека, GeoBlock, логіни) із приблизними пропорціями.\n"
		. "2) Повторювані ризики (один і той самий IP, багато спроб логіну, пікові години, країни GeoBlock).\n"
		. "3) Поясни, що саме означають знайдені події (людською мовою, без жаргону там де можливо).\n"
		. "4) Загальний стан та рівень ризику.\n"
		. "5) Конкретні рекомендації на найближчі кроки (список з 3–7 пунктів).\n\n"
		. "Журнали (останні ~100):\n"
		. implode("\n", array_slice((array)$lines, -100));

	$payload = [
		"model"	=> "gpt-4o-mini",
		"messages" => [
			["role" => "system", "content" => "Ти досвідчений експерт із кібербезпеки WordPress."],
			["role" => "user",   "content" => $prompt]
		],
		"max_tokens"  => 400,
		"temperature" => 0.4
	];

	$endpoint = 'https://api.openai.com/v1/chat/completions';
	$headers  = [
		'Authorization' => 'Bearer ' . CRIT_OPENAI_KEY,
		'Content-Type'  => 'application/json',
		'Accept'		=> 'application/json',
	];

	$debug_log = plugin_dir_path(__FILE__) . 'logs/ai-debug.log';
	$log = function($msg) use ($debug_log){
		@file_put_contents($debug_log, '['.date('Y-m-d H:i:s').'] '.$msg."\n", FILE_APPEND);
	};

	// ---------- Спроба #1: через WP HTTP API (cURL) ----------
	$resp1 = crit_http_post_wp_curl_hard($endpoint, $payload, $headers, 45);
	if (!empty($resp1['ok'])) {
		$data = json_decode($resp1['body'], true);
		$content = $data['choices'][0]['message']['content'] ?? '';
		if ($content !== '') return $content;
		$log('curl ok but empty content: ' . substr($resp1['body'], 0, 800));
		return "⚠️ Відповідь без контенту (cURL). Фрагмент:\n" . substr($resp1['body'], 0, 300);
	} else { $log('curl fail: ' . ($resp1['error'] ?? 'unknown')); }

	// ---------- Спроба #2: streams/OpenSSL ----------
	$resp2 = crit_http_post_wp_streams($endpoint, $payload, $headers, 45);
	if (!empty($resp2['ok'])) {
		$data = json_decode($resp2['body'], true);
		$content = $data['choices'][0]['message']['content'] ?? '';
		if ($content !== '') return $content;
		$log('streams ok but empty content: ' . substr($resp2['body'], 0, 800));
		return "⚠️ Відповідь без контенту (streams). Фрагмент:\n" . substr($resp2['body'], 0, 300);
	} else { $log('streams fail: ' . ($resp2['error'] ?? 'unknown')); }

	// ---------- Спроба #3: raw socket TLS (HTTP/1.1, без gzip, з dechunk) ----------
	$resp3 = crit_http_post_raw_socket($endpoint, $payload, $headers, 45);
	if (!empty($resp3['ok'])) {
		$data = json_decode($resp3['body'], true);
		if (!is_array($data)) {
			$log('socket ok but json_decode failed; raw: ' . substr($resp3['body'], 0, 800));
			return "⚠️ Відповідь без контенту (socket, JSON parse). Фрагмент:\n" . substr($resp3['body'], 0, 300);
		}
		$content = $data['choices'][0]['message']['content'] ?? '';
		if ($content !== '') return $content;
		$log('socket ok but empty content: ' . substr($resp3['body'], 0, 800));
		return "⚠️ Відповідь без контенту (socket). Фрагмент:\n" . substr($resp3['body'], 0, 300);
	} else {
		$log('socket fail: ' . ($resp3['error'] ?? 'unknown') . ' body: ' . substr($resp3['body'] ?? '', 0, 800));
	}

	// Якщо всі шляхи впали — повний звіт
	$err = "❌ Помилка підключення до OpenAI.\n".
		   "cURL: "   . ($resp1['error'] ?? '—') . "\n" .
		   "streams: ". ($resp2['error'] ?? '—') . "\n" .
		   "socket: " . ($resp3['error'] ?? '—') . "\n\n" .
		   "Поради: онови cURL/libcurl і OpenSSL (краще відмовитись від GnuTLS), вимкни HTTP/2/ALPN на проксі,\n" .
		   "перевір системний час та CA-бандл. За потреби додай define('CRIT_OPENAI_FORCE_SOCKET', true) для прямого raw-socket.";
	$log('final fail: ' . str_replace("\n", ' | ', $err));
	return nl2br(esc_html($err));
}

/** Спроба #1: cURL через WP HTTP API з форс-налаштуваннями TLS/HTTP/CA */
function crit_http_post_wp_curl_hard($url, array $payload, array $headers, $timeout = 45) {
	$cafile = crit_guess_wp_cafile();

	// Прямий доступ до cURL handle
	$curl_filter = function($handle){
		if (defined('CURL_HTTP_VERSION_1_1')) {
			@curl_setopt($handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
		}
		if (defined('CURL_SSLVERSION_TLSv1_2')) {
			@curl_setopt($handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
		}
		if (defined('CURLOPT_SSL_ENABLE_ALPN')) @curl_setopt($handle, CURLOPT_SSL_ENABLE_ALPN, false);
		if (defined('CURLOPT_SSL_ENABLE_NPN'))  @curl_setopt($handle, CURLOPT_SSL_ENABLE_NPN, false);
		@curl_setopt($handle, CURLOPT_FORBID_REUSE, true);
		@curl_setopt($handle, CURLOPT_FRESH_CONNECT, true);
	};
	add_action('http_api_curl', $curl_filter, 9999, 1);

	$args = [
		'headers'	 => $headers,
		'body'		=> json_encode($payload),
		'timeout'	 => $timeout,
		'httpversion' => '1.1',
		'sslverify'   => true,
		'blocking'	=> true,
	];
	if ($cafile) $args['sslcertificates'] = $cafile;

	$r = wp_remote_post($url, $args);
	remove_action('http_api_curl', $curl_filter, 9999);

	if (is_wp_error($r)) {
		return ['ok' => false, 'error' => $r->get_error_message()];
	}
	$code = wp_remote_retrieve_response_code($r);
	$body = wp_remote_retrieve_body($r);
	if ($code >= 200 && $code < 300) return ['ok' => true, 'body' => $body];

	$msg = 'HTTP ' . $code;
	$json = json_decode($body, true);
	if (isset($json['error']['message'])) $msg .= ' — ' . $json['error']['message'];
	return ['ok' => false, 'error' => $msg];
}

/** Спроба #2: streams/OpenSSL — жорстко відключаємо cURL-транспорт */
function crit_http_post_wp_streams($url, array $payload, array $headers, $timeout = 45) {
	$cafile = crit_guess_wp_cafile();

	add_filter('use_curl_transport', '__return_false', PHP_INT_MAX);

	$args = [
		'headers'	 => $headers,
		'body'		=> json_encode($payload),
		'timeout'	 => $timeout,
		'httpversion' => '1.1',
		'sslverify'   => true,
		'blocking'	=> true,
	];
	if ($cafile) $args['sslcertificates'] = $cafile;

	$r = wp_remote_post($url, $args);

	remove_filter('use_curl_transport', '__return_false', PHP_INT_MAX);

	if (is_wp_error($r)) {
		return ['ok' => false, 'error' => $r->get_error_message()];
	}
	$code = wp_remote_retrieve_response_code($r);
	$body = wp_remote_retrieve_body($r);
	if ($code >= 200 && $code < 300) return ['ok' => true, 'body' => $body];

	$msg = 'HTTP ' . $code;
	$json = json_decode($body, true);
	if (isset($json['error']['message'])) $msg .= ' — ' . $json['error']['message'];
	return ['ok' => false, 'error' => $msg];
}

/** Декодування HTTP chunked transfer-encoding */
function crit_dechunk_http_body($body) {
	$pos = 0; $len = strlen($body); $out = '';
	while (true) {
		$rn = strpos($body, "\r\n", $pos);
		if ($rn === false) break;
		$line = substr($body, $pos, $rn - $pos);
		if (($sc = strpos($line, ';')) !== false) $line = substr($line, 0, $sc);
		$size = hexdec(trim($line));
		$pos = $rn + 2;
		if ($size <= 0) {
			return $out;
		}
		if ($pos + $size > $len) break;
		$out .= substr($body, $pos, $size);
		$pos += $size + 2; // пропустити \r\n
	}
	return $out ?: $body;
}

/** Спроба #3: raw socket HTTPS із власним HTTP/1.1 запитом (identity + dechunk) */
function crit_http_post_raw_socket($url, array $payload, array $headers, $timeout = 45) {
	if (defined('CRIT_OPENAI_FORCE_SOCKET') && !CRIT_OPENAI_FORCE_SOCKET) {
		return ['ok' => false, 'error' => 'raw-socket вимкнено політикою'];
	}

	$u = parse_url($url);
	if (!$u || empty($u['host'])) return ['ok' => false, 'error' => 'bad URL'];

	$host = $u['host'];
	$port = isset($u['port']) ? intval($u['port']) : 443;
	$path = (isset($u['path']) ? $u['path'] : '/') . (isset($u['query']) ? '?' . $u['query'] : '');

	$cafile = crit_guess_wp_cafile();

	$context_opts = [
		'ssl' => [
			'verify_peer'	   => true,
			'verify_peer_name'  => true,
			'SNI_enabled'	   => true,
			'peer_name'		 => $host,
			'capture_peer_cert' => false,
			'allow_self_signed' => false,
			'crypto_method'	 => defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT')
				? (STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT') ? STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT : 0))
				: (defined('STREAM_CRYPTO_METHOD_TLS_CLIENT') ? STREAM_CRYPTO_METHOD_TLS_CLIENT : 0),
		],
		'http' => [
			'protocol_version' => 1.1
		]
	];
	if ($cafile) $context_opts['ssl']['cafile'] = $cafile;

	$ctx = stream_context_create($context_opts);
	$fp  = @stream_socket_client("ssl://{$host}:{$port}", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
	if (!$fp) {
		return ['ok' => false, 'error' => "socket connect failed: {$errno} {$errstr}"];
	}
	stream_set_timeout($fp, $timeout);

	$body_json = json_encode($payload);
	// важливо: просимо identity, щоб уникнути gzip/deflate
	$req_headers = [
		"POST {$path} HTTP/1.1",
		"Host: {$host}",
		"User-Agent: CriticalLogger/AI",
		"Accept: application/json",
		"Accept-Encoding: identity",
		"Content-Type: application/json",
		"Authorization: Bearer " . CRIT_OPENAI_KEY,
		"Content-Length: " . strlen($body_json),
		"Connection: close",
		"",
		$body_json
	];
	$raw_req = implode("\r\n", $req_headers) . "\r\n";
	fwrite($fp, $raw_req);

	$raw_resp = '';
	while (!feof($fp)) {
		$chunk = fread($fp, 8192);
		if ($chunk === false) break;
		$raw_resp .= $chunk;
	}
	fclose($fp);

	// Розділити заголовки/тіло
	$parts = preg_split("/\r\n\r\n/", $raw_resp, 2);
	if (count($parts) < 2) return ['ok' => false, 'error' => 'bad raw response'];
	$header_block = $parts[0];
	$body		 = $parts[1];

	// Статус
	if (!preg_match('#^HTTP/1\.[01]\s+(\d{3})#', $header_block, $m)) {
		return ['ok' => false, 'error' => 'no HTTP status'];
	}
	$code = intval($m[1]);

	// Розібрати заголовки у масив
	$headers_arr = [];
	foreach (explode("\r\n", $header_block) as $i => $line) {
		if ($i === 0) continue;
		$p = strpos($line, ':');
		if ($p !== false) {
			$name = strtolower(trim(substr($line, 0, $p)));
			$val  = trim(substr($line, $p+1));
			$headers_arr[$name] = $val;
		}
	}

	// Якщо chunked — декодуємо
	if (isset($headers_arr['transfer-encoding']) && stripos($headers_arr['transfer-encoding'], 'chunked') !== false) {
		$body = crit_dechunk_http_body($body);
	}

	if ($code >= 200 && $code < 300) {
		return ['ok' => true, 'body' => $body, 'headers' => $headers_arr, 'status' => $code];
	} else {
		$msg = 'HTTP ' . $code;
		$json = json_decode($body, true);
		if (isset($json['error']['message'])) $msg .= ' — ' . $json['error']['message'];
		return ['ok' => false, 'error' => $msg, 'body' => $body];
	}
}

/**
 * Сторінка AI Insights у меню
 */
add_action('admin_menu', function() {
	add_submenu_page(
		'critical-event-logs',
		'Critical Log Insights (AI)',
		'AI Insights',
		'manage_options',
		'critical-logger-ai',
		'crit_ai_insights_page'
	);
});

/**
 * Інтерфейс AI-аналітики
 */
function crit_ai_insights_page() {
	$ai = crit_ai_generate_insights();

	echo '<div class="wrap"><h1>🤖 Critical Log Insights (AI)</h1>';

	// === Загальний стан + причини ===
	$badge_color = '#2d7'; // green
	if (!empty($ai['risk']['code']) && $ai['risk']['code'] === 'amber') $badge_color = '#f7a600';
	if (!empty($ai['risk']['code']) && $ai['risk']['code'] === 'red')   $badge_color = '#e11';

	echo '<div style="padding:12px 14px;border:1px solid #ddd;border-left:6px solid '.$badge_color.';background:#fff;margin-bottom:14px;border-radius:6px;">';
	$label = is_array($ai['risk']) && isset($ai['risk']['label']) ? $ai['risk']['label'] : '—';
	echo '<div style="font-size:16px;margin-bottom:6px;"><strong>Загальний стан системи:</strong> ' . esc_html($label) . '</div>';

	$reasons = (is_array($ai['risk']) && !empty($ai['risk']['reasons'])) ? $ai['risk']['reasons'] : [];
	if ($reasons) {
		echo '<ul style="margin:6px 0 0 18px;">';
		foreach ($reasons as $r) echo '<li>' . esc_html($r) . '</li>';
		echo '</ul>';
	} else {
		echo '<p style="margin:6px 0 0;">Причин не виявлено.</p>';
	}
	echo '</div>';

	// === Картки-метрики (загалом і за 24 години) ===
	$s = is_array($ai['stats']) ? $ai['stats'] : [];
	$last24 = isset($s['last24']) && is_array($s['last24']) ? $s['last24'] : [
		'errors'=>0,'warnings'=>0,'security'=>0,'geoblock'=>0,'logins'=>0,'total'=>0
	];

	$card = function($title, $value) {
		return '<div style="min-width:140px;background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:10px 12px;">
				  <div style="font-size:12px;color:#666;">'.esc_html($title).'</div>
				  <div style="font-size:18px;font-weight:600;">'.esc_html($value).'</div>
				</div>';
	};

	echo '<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px;">';
	echo $card('Всього рядків', intval($s['total'] ?? 0));
	echo $card('Помилок (all)', intval($s['errors'] ?? 0));
	echo $card('Попереджень (all)', intval($s['warnings'] ?? 0));
	echo $card('Подій безпеки (all)', intval($s['security'] ?? 0));
	echo $card('GeoBlock (all)', intval($s['geoblock'] ?? 0));
	echo $card('Логіни/автентиф.', intval($s['logins'] ?? 0));
	echo $card('Події за 24 год', intval($last24['total']));
	echo $card('Безпека за 24 год', intval($last24['security']));
	echo $card('Унікальних IP', intval($s['unique_ips'] ?? 0));
	echo '</div>';
	// === Розширена деталізація ===
	$dt = isset($ai['details']) && is_array($ai['details']) ? $ai['details'] : [];

	// міні-таблиця-рендер
	$render_table = function($title, array $assoc, $leftHeader, $rightHeader) {
		if (!$assoc) return '';
		$html = '<div style="margin:14px 0;background:#fff;border:1px solid #e5e7eb;border-radius:8px;">';
		$html .= '<div style="padding:10px 12px;border-bottom:1px solid #eee;font-weight:600;">'.esc_html($title).'</div>';
		$html .= '<table class="widefat striped" style="margin:0;border:none;border-top:0;"><thead><tr><th style="width:65%;">'
			. esc_html($leftHeader) . '</th><th style="text-align:right;">' . esc_html($rightHeader) . '</th></tr></thead><tbody>';
		foreach ($assoc as $k => $v) {
			$html .= '<tr><td>'.esc_html($k).'</td><td style="text-align:right;">'.intval($v).'</td></tr>';
		}
		$html .= '</tbody></table></div>';
		return $html;
	};

	echo $render_table('Топ IP-адрес', $dt['top_ip'] ?? [], 'IP', 'К-сть');
	echo $render_table('Топ користувачів', $dt['top_users'] ?? [], 'Користувач', 'К-сть');
	echo $render_table('GeoBlock країни', $dt['top_countries'] ?? [], 'Країна', 'К-сть');
	echo $render_table('Рівні подій', $dt['top_levels'] ?? [], 'Рівень', 'К-сть');
	echo $render_table('Типові повідомлення', $dt['top_messages'] ?? [], 'Шаблон повідомлення', 'К-сть');

	// часовий розподіл (мікро-гістограма)
	if (!empty($dt['hours_hist']) && is_array($dt['hours_hist'])) {
		$hist = $dt['hours_hist'];
		ksort($hist);
		$maxv = max($hist);
		echo '<div style="margin:14px 0;background:#fff;border:1px solid #e5e7eb;border-radius:8px;">';
		echo '<div style="padding:10px 12px;border-bottom:1px solid #eee;font-weight:600;">Розподіл за годинами</div>';
		echo '<div style="padding:10px 12px">';
		foreach ($hist as $hour => $val) {
			$w = $maxv ? max(2, (int)round(($val/$maxv)*100)) : 2;
			echo '<div style="display:flex;align-items:center;gap:8px;margin:4px 0;">'
			   . '<div style="width:120px;color:#666;font-size:12px;">'.esc_html($hour).'</div>'
			   . '<div style="flex:1;background:#f1f5f9;border-radius:4px;overflow:hidden;"><div style="height:8px;width:'.$w.'%;background:#3b82f6;"></div></div>'
			   . '<div style="width:36px;text-align:right;font-size:12px;color:#555;">'.intval($val).'</div>'
			   . '</div>';
		}
		echo '</div></div>';
	}

	// Останні інциденти
	$last_err = $dt['last_errors'] ?? [];
	$last_sec = $dt['last_security'] ?? [];
	if ($last_err) {
		echo '<div style="margin:14px 0;background:#fff;border:1px solid #e5e7eb;border-radius:8px;">';
		echo '<div style="padding:10px 12px;border-bottom:1px solid #eee;font-weight:600;">Останні помилки</div>';
		echo '<pre style="margin:0;padding:10px 12px;max-height:220px;overflow:auto;white-space:pre-wrap;">';
		foreach ($last_err as $l) echo esc_html($l)."\n";
		echo '</pre></div>';
	}
	if ($last_sec) {
		echo '<div style="margin:14px 0;background:#fff;border:1px solid #e5e7eb;border-radius:8px;">';
		echo '<div style="padding:10px 12px;border-bottom:1px solid #eee;font-weight:600;">Останні події безпеки / GeoBlock</div>';
		echo '<pre style="margin:0;padding:10px 12px;max-height:220px;overflow:auto;white-space:pre-wrap;">';
		foreach ($last_sec as $l) echo esc_html($l)."\n";
		echo '</pre></div>';
	}

	// === Кнопка для AI-аналізу ===
	if (isset($_POST['run_ai_analysis'])) {
		check_admin_referer('crit_ai_run_analysis', 'crit_ai_nonce');
		echo '<p><em>⏳ Зачекай, AI аналізує журнали...</em></p>';
		$analysis = crit_ai_analyze_logs_with_openai($ai['raw']);
		echo '<h2>🧩 AI-висновок:</h2>';
		echo '<div style="background:#fff;border:1px solid #ccc;padding:15px;white-space:pre-wrap;">' . esc_html($analysis) . '</div>';
	}

	echo '<form method="post" style="margin-top:20px;">';
	wp_nonce_field('crit_ai_run_analysis', 'crit_ai_nonce');
	echo '<input type="submit" name="run_ai_analysis" class="button-primary" value="🔁 Аналізувати зараз">';
	echo '</form>';

	// === Сиру вибірку логів (останні 100) ===
	echo '<h3>Останні 100 рядків логів</h3>';
	echo '<div style="max-height:300px;overflow-y:auto;background:#f9f9f9;border:1px solid #ddd;padding:10px;font-family:monospace;font-size:13px;">';
	foreach ($ai['raw'] as $line) {
		echo esc_html($line) . "\n";
	}
	echo '</div>';

	echo '<hr><p style="color:#777;">Цей модуль використовує API OpenAI (GPT-4o-mini або GPT-5) для генерації короткого аналізу логів.</p>';
	echo '</div>';
}
