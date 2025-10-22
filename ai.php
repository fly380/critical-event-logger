<?php
/**
 * Critical Event Logger — helper module
 * Copyright © 2025 Казмірчук Андрій
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if (!defined('ABSPATH')) exit;

// ---- Єдиний геттер ключа OpenAI (пріоритет: БД -> константа; врахуємо і $GLOBALS з intel) ----
if (!function_exists('crit_get_option_or_const')) {
	function crit_get_option_or_const(string $const_name, string $option_name): string {
		$opt = trim((string) get_option($option_name, ''));
		if ($opt !== '') return $opt;

		if (defined($const_name)) {
			$val = trim((string) constant($const_name));
			if ($val !== '') return $val;
		}
		return '';
	}
}

/** Отримати OpenAI API key: БД -> константа -> $GLOBALS['CL_AI_KEY'] */
function crit_get_openai_key(): string {
	static $key = null;
	if ($key !== null) return $key;

	if (isset($GLOBALS['CL_AI_KEY'])) {
		$k = trim((string)$GLOBALS['CL_AI_KEY']);
		if ($k !== '') { $key = $k; return $key; }
	}
	$key = crit_get_option_or_const('CRIT_OPENAI_KEY', 'crit_openai_key');
	return $key;
}

/** Прочитати хвіст великого файлу (за замовчуванням ~512КБ) */
function crit_tail_file(string $path, int $bytes = 524288): string {
	$f = @fopen($path, 'rb');
	if (!$f) return '';
	@fseek($f, 0, SEEK_END);
	$size = @ftell($f);
	$seek = max(0, (int)$size - $bytes);
	@fseek($f, $seek, SEEK_SET);
	$data = @stream_get_contents($f) ?: '';
	@fclose($f);
	return $data;
}

// 1) Розрізати файл на окремі записи навіть без \n між ними
if (!function_exists('crit_split_log_entries')) {
	function crit_split_log_entries(string $raw): array {
		$raw = trim($raw);
		if ($raw === '') return [];
		$parts = preg_split('/(?=\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\])/', $raw);
		return array_values(array_filter(array_map('trim', $parts), static function($s){ return $s !== ''; }));
	}
}
// 1) (опційно) додай редактр перед відправкою
if (!function_exists('crit_ai_scrub_lines')) {
	function crit_ai_scrub_lines(array $lines): array {
		$out = [];
		foreach ($lines as $s) {
			// auth-заголовки / токени / cookies
			$s = preg_replace('/(Authorization:\s*(Bearer|Basic)\s+)[^\s]+/i', '$1<redacted>', $s);
			$s = preg_replace('/\b(X-?Api|X-?Auth|Auth|Token|Api[-\s]?Key)\s*[:=]\s*[A-Za-z0-9._\-~+\/=]+/i', '$1: <redacted>', $s);
			$s = preg_replace('/\b(Set-Cookie|Cookie)\s*:\s*[^\r\n]+/i', '$1: <redacted>', $s);

			// паролі/секрети/nonce у query/body
			$s = preg_replace('/([\?&](pass(word)?|pwd|secret|token|code|key|nonce))=([^&\s]+)/i', '$1=<redacted>', $s);
			$s = preg_replace('/\bwp_nonce=[A-Za-z0-9_-]+\b/i', 'wp_nonce=<redacted>', $s);

			// довгі хеші/токени
			$s = preg_replace('/\b[0-9a-f]{32,}\b/i', '<hash>', $s);

			// e-mail
			$s = preg_replace('/[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}/i', '<email>', $s);

			// IPv4 / IPv6
			$s = preg_replace('/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', '<ip>', $s);
			$s = preg_replace('/\b([0-9a-f]{1,4}:){1,7}[0-9a-f]{1,4}\b/i', '<ip6>', $s);

			$out[] = $s;
		}
		return $out;
	}
}

// 2) Парс одного запису у структуру (IPv4/IPv6)
function crit_ai_parse_line(string $line): array {
	$time = $ip = $user = $level = $msg = $tag = '';
	if (preg_match('/^\[([0-9\- :]+)\]\[([^\]]+)\]\[([^\]]*)\]\[([^\]]+)\]\s?(.*)$/u', $line, $m)) {
		$time  = $m[1];
		$iptag = trim($m[2]);
		$user  = trim($m[3]);
		$level = trim($m[4]);
		$msg   = $m[5];

		if (filter_var($iptag, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
			$ip = $iptag;
		} else {
			$tag = $iptag;
			if (preg_match('/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', $msg, $mm)) {
				$ip = $mm[1];
			} else {
				if (preg_match_all('/[0-9a-f:]{2,}/i', $msg, $mm6)) {
					foreach ($mm6[0] as $cand) {
						if (filter_var($cand, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) { $ip = $cand; break; }
					}
				}
			}
		}
	} else {
		if (preg_match('/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', $line, $mm)) {
			$ip = $mm[1];
		} else {
			if (preg_match_all('/[0-9a-f:]{2,}/i', $line, $mm6)) {
				foreach ($mm6[0] as $cand) {
					if (filter_var($cand, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) { $ip = $cand; break; }
				}
			}
		}
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

// 3) Топ N
function crit_ai_topN(array $counts, int $n = 10): array {
	arsort($counts);
	return array_slice($counts, 0, $n, true);
}

/** Зчитує лог-файл та готує аналітику (tail + кеш 60с, таймзона WP) */
function crit_ai_generate_insights($limit = 300) {
	$log_file = plugin_dir_path(__FILE__) . 'logs/events.log';
	if (!file_exists($log_file)) {
		return [
			'risk' => ['code'=>'unknown','label'=>'⚠️ Логів не знайдено','reasons'=>['Файл logs/events.log відсутній або порожній.']],
			'stats'=>[], 'raw'=>[], 'details'=>[]
		];
	}

	$sig  = @filemtime($log_file) . '|' . @filesize($log_file) . '|' . (int)$limit;
	$ckey = 'crit_ai_insights_' . md5($sig);
	if (($cached = get_transient($ckey))) return $cached;

	$raw = crit_tail_file($log_file, 524288);
	if ($raw === '') $raw = @file_get_contents($log_file) ?: '';
	$entries = crit_split_log_entries($raw);
	if (!$entries) {
		$res = [
			'risk' => ['code'=>'unknown','label'=>'⚠️ Порожній лог','reasons'=>['Вміст файлу відсутній.']],
			'stats'=>[], 'raw'=>[], 'details'=>[]
		];
		set_transient($ckey, $res, 60);
		return $res;
	}

	$entries = array_slice($entries, -$limit);

	$stats = [
		'total'=>count($entries),'errors'=>0,'warnings'=>0,'security'=>0,'geoblock'=>0,'logins'=>0,
		'last24'=>['errors'=>0,'warnings'=>0,'security'=>0,'geoblock'=>0,'logins'=>0,'total'=>0]
	];

	$now    = (int) current_time('timestamp');
	$dayAgo = $now - DAY_IN_SECONDS;

	$cnt_ip=[];$cnt_user=[];$cnt_country=[];$cnt_level=[];$cnt_messages=[];$hours_hist=[];
	$last_errors=[];$last_security=[];$unique_ips=[];

	foreach ($entries as $line) {
		$rec = crit_ai_parse_line($line);

		$is_last24 = false;
		if (!empty($rec['time'])) {
			$ts = strtotime($rec['time']);
			if ($ts !== false && $ts >= $dayAgo) { $is_last24 = true; $stats['last24']['total']++; }
			$hourKey = $ts ? date('Y-m-d H', $ts) : '';
			if ($hourKey) $hours_hist[$hourKey] = ($hours_hist[$hourKey] ?? 0) + 1;
		}

		$level = $rec['level'];
		if ($level) $cnt_level[$level] = ($cnt_level[$level] ?? 0) + 1;

		$has_error   = ($level === 'ERROR');
		$has_warning = ($level === 'WARN' || $level === 'WARNING');
		$has_sec     = ($level === 'SECURITY');
		$has_geo     = (strcasecmp($rec['tag'], 'GeoBlock') === 0) || stripos($rec['msg'], 'GeoBlock') !== false;
		$has_login   = (stripos($rec['msg'], 'login') !== false || stripos($rec['msg'], 'автентиф') !== false || stripos($rec['msg'], 'вхід') !== false);

		if ($has_error)   { $stats['errors']++;   if ($is_last24) $stats['last24']['errors']++; }
		if ($has_warning) { $stats['warnings']++; if ($is_last24) $stats['last24']['warnings']++; }
		if ($has_sec)     { $stats['security']++; if ($is_last24) $stats['last24']['security']++; }
		if ($has_geo)     { $stats['geoblock']++; if ($is_last24) $stats['last24']['geoblock']++; }
		if ($has_login)   { $stats['logins']++;   if ($is_last24) $stats['last24']['logins']++; }

		if ($rec['ip']) { $unique_ips[$rec['ip']] = true; $cnt_ip[$rec['ip']] = ($cnt_ip[$rec['ip']] ?? 0) + 1; }
		if ($rec['user']) { $u = trim($rec['user']) ?: 'guest'; $cnt_user[$u] = ($cnt_user[$u] ?? 0) + 1; }

		if ($has_geo && preg_match('/\b([A-Z]{2})\b/', $rec['msg'], $gm)) {
			$cc = $gm[1]; $cnt_country[$cc] = ($cnt_country[$cc] ?? 0) + 1;
		}

		$norm = preg_replace([
			'/\b\d{1,3}(?:\.\d{1,3}){3}\b/',
			'/[0-9a-f:]{2,}/i',
			'/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i',
			'/\d+/'
		], ['<ip>','<ip6>','<email>','<n>'], mb_strtolower($rec['msg']));
		$norm = trim($norm);
		if ($norm !== '') $cnt_messages[$norm] = ($cnt_messages[$norm] ?? 0) + 1;

		if ($has_error && count($last_errors) < 5) $last_errors[] = $line;
		if (($has_sec || $has_geo) && count($last_security) < 5) $last_security[] = $line;
	}

	$top_ip        = crit_ai_topN($cnt_ip, 10);
	$top_users     = crit_ai_topN($cnt_user, 10);
	$top_countries = crit_ai_topN($cnt_country, 10);
	$top_levels    = crit_ai_topN($cnt_level, 10);
	$top_messages  = crit_ai_topN($cnt_messages, 10);

	$anomalies = [];
	$uniq_ip_count = count($unique_ips);
	if ($stats['security'] > 20) $anomalies[] = "Висока кількість подій безпеки: {$stats['security']} (порог >20)";
	if ($stats['errors'] > 10)   $anomalies[] = "Багато помилок: {$stats['errors']} (порог >10)";
	if (!empty($top_ip)) {
		$firstIp = array_key_first($top_ip);
		if ($top_ip[$firstIp] >= max(5, (int)ceil($stats['total'] * 0.1))) $anomalies[] = "IP {$firstIp} з’являється дуже часто: {$top_ip[$firstIp]} раз(ів)";
	}
	if (!empty($hours_hist)) {
		arsort($hours_hist);
		$bigHour = array_key_first($hours_hist);
		if ($hours_hist[$bigHour] >= max(10, (int)ceil($stats['total'] * 0.2))) $anomalies[] = "Сплеск подій у годину {$bigHour}: {$hours_hist[$bigHour]} записів";
	}

	$reasons = [];
	$risk_code  = 'green';
	$risk_label = '🟢 Стабільно';

	if ($stats['warnings'] > 10)  $reasons[] = "Попереджень: {$stats['warnings']} (>10)";
	if ($stats['security'] > 5)   $reasons[] = "Подій безпеки: {$stats['security']} (>5)";
	if ($stats['last24']['security'] > 0) $reasons[] = "Є події безпеки за 24 год: {$stats['last24']['security']}";
	if ($stats['geoblock'] > 0)   $reasons[] = "Блокувань GeoBlock: {$stats['geoblock']}";

	$danger_reasons = [];
	if ($stats['errors'] > 10)   $danger_reasons[] = "Помилок: {$stats['errors']} (>10)";
	if ($stats['security'] > 20) $danger_reasons[] = "Подій безпеки: {$stats['security']} (>20)";

	if (!empty($danger_reasons)) {
		$risk_code  = 'red';
		$risk_label = '🔴 Небезпечно';
		$reasons = array_merge($danger_reasons, $reasons);
	} elseif (!empty($reasons)) {
		$risk_code  = 'amber';
		$risk_label = '🟠 Попередження';
	}
	$reasons = array_merge($reasons, $anomalies);

	$res = [
		'risk' => ['code'=>$risk_code,'label'=>$risk_label,'reasons'=>$reasons ?: ['В аномаліях не помічено перевищення порогів.']],
		'stats'=> array_merge($stats, ['unique_ips'=>$uniq_ip_count]),
		'raw'  => array_slice($entries, -100),
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

	set_transient($ckey, $res, 60);
	return $res;
}

/** Повертає шлях до WP CA bundle або null */
function crit_guess_wp_cafile() {
	$cafile = ABSPATH . WPINC . '/certificates/ca-bundle.crt';
	return file_exists($cafile) ? $cafile : null;
}

/** Генерує аналітичний звіт через OpenAI */
function crit_ai_analyze_logs_with_openai($lines) {
	$apiKey = crit_get_openai_key();
	if ($apiKey === '') {
		return '⚠️ Відсутній API-ключ OpenAI. Додай його в налаштуваннях плагіна (опція crit_openai_key) або через константу CRIT_OPENAI_KEY у wp-config.php';
	}
	$safe_lines = crit_ai_scrub_lines(array_slice((array)$lines, -100));

	$prompt = "Ти — аналітик безпеки WordPress. Проаналізуй уривки журналів подій і дай короткий, чіткий звіт українською:\n"
		. "1) Домінуючі типи подій (помилки, безпека, GeoBlock, логіни) із приблизними пропорціями.\n"
		. "2) Повторювані ризики (один і той самий IP, багато спроб логіну, пікові години, країни GeoBlock).\n"
		. "3) Поясни, що саме означають знайдені події.\n"
		. "4) Загальний стан та рівень ризику.\n"
		. "5) 3–7 конкретних рекомендацій.\n\n"
		. "Журнали (останні ~100):\n"
		. implode("\n", $safe_lines);

	$payload = [
		"model"    => "gpt-4o-mini",
		"messages" => [
			["role" => "system", "content" => "Ти досвідчений експерт із кібербезпеки WordPress."],
			["role" => "user",   "content" => $prompt]
		],
		"max_tokens"  => 400,
		"temperature" => 0.4
	];

	$endpoint = 'https://api.openai.com/v1/chat/completions';
	$headers  = ['Authorization'=>'Bearer '.$apiKey,'Content-Type'=>'application/json','Accept'=>'application/json'];

	$debug_log = plugin_dir_path(__FILE__) . 'logs/ai-debug.log';
	$log = function($msg) use ($debug_log){ @file_put_contents($debug_log, '['.date('Y-m-d H:i:s').'] '.$msg."\n", FILE_APPEND); };

	$resp1 = crit_http_post_wp_curl_hard($endpoint, $payload, $headers, 45);
	if (!empty($resp1['ok'])) {
		$data = json_decode($resp1['body'], true);
		$content = $data['choices'][0]['message']['content'] ?? '';
		if ($content !== '') return $content;
		$log('curl ok but empty content: ' . substr($resp1['body'], 0, 800));
		return "⚠️ Відповідь без контенту (cURL). Фрагмент:\n" . substr($resp1['body'], 0, 300);
	} else { $log('curl fail: ' . ($resp1['error'] ?? 'unknown')); }

	$resp2 = crit_http_post_wp_streams($endpoint, $payload, $headers, 45);
	if (!empty($resp2['ok'])) {
		$data = json_decode($resp2['body'], true);
		$content = $data['choices'][0]['message']['content'] ?? '';
		if ($content !== '') return $content;
		$log('streams ok but empty content: ' . substr($resp2['body'], 0, 800));
		return "⚠️ Відповідь без контенту (streams). Фрагмент:\n" . substr($resp2['body'], 0, 300);
	} else { $log('streams fail: ' . ($resp2['error'] ?? 'unknown')); }

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

	$err = "❌ Помилка підключення до OpenAI.\n".
		   "cURL: "   . ($resp1['error'] ?? '—') . "\n" .
		   "streams: ". ($resp2['error'] ?? '—') . "\n" .
		   "socket: " . ($resp3['error'] ?? '—') . "\n\n" .
		   "Поради: онови cURL/libcurl і OpenSSL, вимкни HTTP/2/ALPN на проксі, перевір час та CA-бандл.";
	$log('final fail: ' . str_replace("\n", ' | ', $err));
	return nl2br(esc_html($err));
}

/** HTTP helpers */
function crit_http_post_wp_curl_hard($url, array $payload, array $headers, $timeout = 45) {
	$cafile = crit_guess_wp_cafile();
	$curl_filter = function($handle){
		if (defined('CURL_HTTP_VERSION_1_1')) @curl_setopt($handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
		if (defined('CURL_SSLVERSION_TLSv1_2')) @curl_setopt($handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
		if (defined('CURLOPT_SSL_ENABLE_ALPN')) @curl_setopt($handle, CURLOPT_SSL_ENABLE_ALPN, false);
		if (defined('CURLOPT_SSL_ENABLE_NPN'))  @curl_setopt($handle, CURLOPT_SSL_ENABLE_NPN, false);
		@curl_setopt($handle, CURLOPT_FORBID_REUSE, true);
		@curl_setopt($handle, CURLOPT_FRESH_CONNECT, true);
	};
	add_action('http_api_curl', $curl_filter, 9999, 1);

	$args = ['headers'=>$headers,'body'=>json_encode($payload),'timeout'=>$timeout,'httpversion'=>'1.1','sslverify'=>true,'blocking'=>true];
	if ($cafile) $args['sslcertificates'] = $cafile;

	$r = wp_remote_post($url, $args);
	remove_action('http_api_curl', $curl_filter, 9999);

	if (is_wp_error($r)) return ['ok'=>false,'error'=>$r->get_error_message()];
	$code = wp_remote_retrieve_response_code($r);
	$body = wp_remote_retrieve_body($r);
	if ($code >= 200 && $code < 300) return ['ok'=>true,'body'=>$body];

	$msg = 'HTTP ' . $code;
	$json = json_decode($body, true);
	if (isset($json['error']['message'])) $msg .= ' — ' . $json['error']['message'];
	return ['ok'=>false,'error'=>$msg];
}

function crit_http_post_wp_streams($url, array $payload, array $headers, $timeout = 45) {
	$cafile = crit_guess_wp_cafile();
	add_filter('use_curl_transport', '__return_false', PHP_INT_MAX);
	$args = ['headers'=>$headers,'body'=>json_encode($payload),'timeout'=>$timeout,'httpversion'=>'1.1','sslverify'=>true,'blocking'=>true];
	if ($cafile) $args['sslcertificates'] = $cafile;
	$r = wp_remote_post($url, $args);
	remove_filter('use_curl_transport', '__return_false', PHP_INT_MAX);

	if (is_wp_error($r)) return ['ok'=>false,'error'=>$r->get_error_message()];
	$code = wp_remote_retrieve_response_code($r);
	$body = wp_remote_retrieve_body($r);
	if ($code >= 200 && $code < 300) return ['ok'=>true,'body'=>$body];

	$msg = 'HTTP ' . $code;
	$json = json_decode($body, true);
	if (isset($json['error']['message'])) $msg .= ' — ' . $json['error']['message'];
	return ['ok'=>false,'error'=>$msg];
}

function crit_dechunk_http_body($body) {
	$pos = 0; $len = strlen($body); $out = '';
	while (true) {
		$rn = strpos($body, "\r\n", $pos);
		if ($rn === false) break;
		$line = substr($body, $pos, $rn - $pos);
		if (($sc = strpos($line, ';')) !== false) $line = substr($line, 0, $sc);
		$size = hexdec(trim($line));
		$pos = $rn + 2;
		if ($size <= 0) return $out;
		if ($pos + $size > $len) break;
		$out .= substr($body, $pos, $size);
		$pos += $size + 2;
	}
	return $out ?: $body;
}

function crit_http_post_raw_socket($url, array $payload, array $headers, $timeout = 45) {
	if (defined('CRIT_OPENAI_FORCE_SOCKET') && !CRIT_OPENAI_FORCE_SOCKET) return ['ok'=>false,'error'=>'raw-socket вимкнено політикою'];

	$u = parse_url($url);
	if (!$u || empty($u['host'])) return ['ok'=>false,'error'=>'bad URL'];

	$host = $u['host'];
	$port = isset($u['port']) ? intval($u['port']) : 443;
	$path = (isset($u['path']) ? $u['path'] : '/') . (isset($u['query']) ? '?' . $u['query'] : '');

	$cafile = crit_guess_wp_cafile();

	$context_opts = [
		'ssl' => [
			'verify_peer'=>true,'verify_peer_name'=>true,'SNI_enabled'=>true,'peer_name'=>$host,'capture_peer_cert'=>false,'allow_self_signed'=>false,
			'crypto_method'=> defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT')
				? (STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT') ? STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT : 0))
				: (defined('STREAM_CRYPTO_METHOD_TLS_CLIENT') ? STREAM_CRYPTO_METHOD_TLS_CLIENT : 0),
		],
		'http' => ['protocol_version' => 1.1]
	];
	if ($cafile) $context_opts['ssl']['cafile'] = $cafile;

	$ctx = stream_context_create($context_opts);
	$fp  = @stream_socket_client("ssl://{$host}:{$port}", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
	if (!$fp) return ['ok'=>false,'error'=>"socket connect failed: {$errno} {$errstr}"];
	stream_set_timeout($fp, $timeout);

	$body_json = json_encode($payload);
	$authHeader = $headers['Authorization'] ?? ('Bearer ' . crit_get_openai_key());

	$req_headers = [
		"POST {$path} HTTP/1.1","Host: {$host}","User-Agent: CriticalLogger/AI",
		"Accept: application/json","Accept-Encoding: identity","Content-Type: application/json",
		"Authorization: {$authHeader}","Content-Length: " . strlen($body_json),"Connection: close","",$body_json
	];
	@fwrite($fp, implode("\r\n", $req_headers) . "\r\n");

	$raw_resp = '';
	while (!feof($fp)) { $chunk = @fread($fp, 8192); if ($chunk === false) break; $raw_resp .= $chunk; }
	@fclose($fp);

	$parts = preg_split("/\r\n\r\n/", $raw_resp, 2);
	if (count($parts) < 2) return ['ok'=>false,'error'=>'bad raw response'];
	$header_block = $parts[0]; $body = $parts[1];

	if (!preg_match('#^HTTP/1\.[01]\s+(\d{3})#', $header_block, $m)) return ['ok'=>false,'error'=>'no HTTP status'];
	$code = intval($m[1]);

	$headers_arr = [];
	foreach (explode("\r\n", $header_block) as $i => $line) {
		if ($i === 0) continue;
		$p = strpos($line, ':');
		if ($p !== false) { $name = strtolower(trim(substr($line, 0, $p))); $val = trim(substr($line, $p+1)); $headers_arr[$name] = $val; }
	}
	if (isset($headers_arr['transfer-encoding']) && stripos($headers_arr['transfer-encoding'], 'chunked') !== false) {
		$body = crit_dechunk_http_body($body);
	}

	if ($code >= 200 && $code < 300) return ['ok'=>true,'body'=>$body,'headers'=>$headers_arr,'status'=>$code];
	$msg = 'HTTP ' . $code;
	$json = json_decode($body, true);
	if (isset($json['error']['message'])) $msg .= ' — ' . $json['error']['message'];
	return ['ok'=>false,'error'=>$msg,'body'=>$body];
}

/** =========================
 *   МЕНЮ + СКРИПТИ ДЛЯ ГРАФІКІВ
 *  ========================= */

add_action('admin_menu', function() {
	$GLOBALS['crit_ai_hook'] = add_submenu_page(
		'critical-event-logs',
		'AI аналітика логу',
		'AI аналітика',
		'manage_options',
		'critical-logger-ai',
		'crit_ai_insights_page'
	);
});

add_action('admin_enqueue_scripts', function($hook) {
	if (empty($GLOBALS['crit_ai_hook']) || $hook !== $GLOBALS['crit_ai_hook']) return;

	// UMD-збірка -> window.Chart
	wp_register_script(
		'chartjs',
		'https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js',
		[],
		'4.4.1',
		true
	);
	wp_enqueue_script('chartjs');

	$ai = crit_ai_generate_insights();
	$dt = is_array($ai['details'] ?? null) ? $ai['details'] : [];

	$byDay = [];
	if (!empty($dt['hours_hist']) && is_array($dt['hours_hist'])) {
		foreach ($dt['hours_hist'] as $hour => $cnt) {
			$day = substr($hour, 0, 10);
			$byDay[$day] = ($byDay[$day] ?? 0) + (int)$cnt;
		}
		ksort($byDay);
		if (count($byDay) > 30) $byDay = array_slice($byDay, -30, null, true);
	}

	$payload = [
		'byDay' => ['labels' => array_values(array_keys($byDay)), 'values' => array_values($byDay)],
		'byCountry' => [
			'labels' => array_keys(array_slice($dt['top_countries'] ?? [], 0, 8, true)),
			'values' => array_values(array_slice($dt['top_countries'] ?? [], 0, 8, true)),
		],
		'byIp' => [
			'labels' => array_keys(array_slice($dt['top_ip'] ?? [], 0, 8, true)),
			'values' => array_values(array_slice($dt['top_ip'] ?? [], 0, 8, true)),
		],
	];

	$inline = '(function(){
  const D = '.wp_json_encode($payload).';

  function onReady(fn){ if(document.readyState!=="loading"){fn();} else {document.addEventListener("DOMContentLoaded",fn,{once:true});} }
  function hasData(arr){ return Array.isArray(arr) && arr.some(function(v){ return (+v||0) > 0; }); }
  function toNum(arr){ return Array.isArray(arr) ? arr.map(function(v){ return +v||0; }) : []; }

  function showEmpty(el){
    const p = el.parentElement; if(!p) return;
    p.style.display="grid"; p.style.placeItems="center"; p.style.minHeight="120px";
    const msg=document.createElement("div"); msg.textContent="Немає даних";
    msg.style.color="#64748b"; msg.style.fontSize="12px"; p.replaceChild(msg, el);
  }

  onReady(function(){
    if(typeof window.Chart==="undefined"){ console.warn("Chart.js не завантажено"); return; }

    const basePlugins = { legend:{display:false}, tooltip:{padding:6,bodyFont:{size:11},titleFont:{size:11}} };
    const baseOpts    = { responsive:true, maintainAspectRatio:false, resizeDelay:150, animation:false, layout:{padding:{top:0,right:6,bottom:0,left:6}} };

    function baseScales(isH){
      const cut = function(lbl){ lbl=String(lbl); return lbl.length>18 ? lbl.slice(0,18)+"…" : lbl; };
      return isH ? {
        x:{ beginAtZero:true, grid:{color:"#f1f5f9"}, ticks:{font:{size:10}} },
        y:{ grid:{display:false}, ticks:{font:{size:10}, callback:function(v,i){ const l=(this.getLabelForValue?this.getLabelForValue(v):(this.chart.data.labels[i]??v)); return cut(l);} } }
      } : {
        x:{ grid:{display:false}, ticks:{font:{size:10}, autoSkip:true, maxTicksLimit:8} },
        y:{ beginAtZero:true, grid:{color:"#f1f5f9"}, ticks:{font:{size:10}} }
      };
    }

    // Лінія: події по днях
    (function(){
      const el = document.getElementById("critByDay"); if(!el) return;
      const vals = toNum(D.byDay.values);
      if(!Array.isArray(D.byDay.labels) || D.byDay.labels.length===0 || !hasData(vals)) { showEmpty(el); return; }

      const maxV = Math.max.apply(null, vals.concat([0]));
      new Chart(el.getContext("2d"), {
        type:"line",
        data:{ labels:D.byDay.labels, datasets:[{
          data: vals, tension:.3, borderWidth:1.5, pointRadius:0, fill:true,
          borderColor:"rgba(59,130,246,1)", backgroundColor:"rgba(59,130,246,.18)"
        }]},
        options:Object.assign({}, baseOpts, {
          scales: Object.assign(baseScales(false), { y: Object.assign(baseScales(false).y, { suggestedMax: Math.max(5, maxV) }) }),
          plugins: basePlugins
        })
      });
    })();

    // Горизонтальні стовпчики (topN)
    function renderHBar(id, L, V){
      const el = document.getElementById(id); if(!el) return;
      const vals = toNum(V);
      if(!Array.isArray(L) || L.length===0 || !hasData(vals)) { showEmpty(el); return; }
      const maxV = Math.max.apply(null, vals.concat([0]));
      new Chart(el.getContext("2d"), {
        type:"bar",
        data:{ labels:L, datasets:[{ data: vals, borderWidth:1, backgroundColor:"rgba(99,102,241,.7)"}] },
        options:Object.assign({}, baseOpts, {
          indexAxis:"y",
          scales: Object.assign(baseScales(true), { x: Object.assign(baseScales(true).x, { suggestedMax: Math.max(5, maxV) }) }),
          plugins: basePlugins,
          datasets:{ bar:{ barThickness:10, categoryPercentage:.7, barPercentage:.7 } }
        })
      });
    }

    renderHBar("critByCountry", D.byCountry.labels, D.byCountry.values);
    renderHBar("critByIp",      D.byIp.labels,      D.byIp.values);
  });
})();';
	wp_add_inline_script('chartjs', $inline, 'after');

});

/** Інтерфейс AI-аналітики (+ лише графіки, без дублюючих таблиць) */
function crit_ai_insights_page() {
	$ai = crit_ai_generate_insights();

	echo '<div class="wrap">';
	echo '<div class="crit-admin-header" style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:8px;">';
	echo '<h1 style="margin:0;">AI аналітика логу</h1>';
	echo '<button id="crit-ai-info-open" type="button" class="button button-secondary" aria-haspopup="dialog" aria-expanded="false" aria-controls="crit-ai-info-modal">Info</button>';
	echo '</div>';
	?>
<style id="crit-ai-info-modal-css">
	#crit-ai-info-modal[hidden]{display:none;}
	#crit-ai-info-modal{position:fixed;inset:0;z-index:100000;}
	#crit-ai-info-modal .crit-modal__backdrop{position:absolute;inset:0;background:rgba(0,0,0,.35);}
	#crit-ai-info-modal .crit-modal__dialog{
		position:relative;max-width:820px;margin:6vh auto;background:#fff;border-radius:8px;
		box-shadow:0 10px 30px rgba(0,0,0,.2);padding:20px 22px;outline:0;
	}
	#crit-ai-info-modal h2{margin:0 32px 10px 0;}
	#crit-ai-info-modal .crit-modal__body{line-height:1.55;max-height:65vh;overflow:auto;padding-right:2px;}
	#crit-ai-info-modal .crit-modal__close{
		position:absolute;right:12px;top:10px;border:0;background:transparent;font-size:22px;line-height:1;cursor:pointer;
	}
	#crit-ai-info-modal .crit-kbd{display:inline-block;border:1px solid #ddd;border-bottom-width:2px;border-radius:4px;padding:0 5px;font:12px/20px monospace;background:#f8f8f8}
	#crit-ai-info-modal ul{margin:0 0 10px 18px}
	#crit-ai-info-modal li{margin:6px 0}
	#crit-ai-info-modal code{background:#f6f7f7;border:1px solid #e2e4e7;border-radius:3px;padding:1px 4px}
</style>
<div id="crit-ai-info-modal" role="dialog" aria-modal="true" aria-labelledby="crit-ai-info-title" hidden>
	<div class="crit-modal__backdrop" data-close="1"></div>
	<div class="crit-modal__dialog" role="document" tabindex="-1">
		<button type="button" class="crit-modal__close" id="crit-ai-info-close" aria-label="Закрити" title="Закрити (Esc)">×</button>
		<h2 id="crit-ai-info-title">Що вміє модуль «AI аналітика»</h2>
		<div class="crit-modal__body">
			<ul>
				<li><strong>Загальний стан</strong> — бейдж (<em>🟢/🟠/🔴</em>) з причинами. Пороги беруться з фактичних метрик (помилки, безпека, GeoBlock, сплески за годинами).</li>
				<li><strong>Картки-метрики</strong> — всього рядків, помилки/попередження/безпека/GeoBlock/логіни, події за 24 год, унікальні IP.</li>
				<li><strong>Графіки</strong> (Chart.js):
					<ul>
						<li><em>Події по днях</em> — агреговані підсумки за останні ~30 дат.</li>
						<li><em>Топ країн (Geo)</em> і <em>Топ IP</em> — топ-8 за частотою.</li>
						<li><em>Розподіл за годинами</em> — мікро-гістограма сплесків.</li>
					</ul>
				</li>
				<li><strong>Останні фрагменти</strong> — списки «Останні помилки» та «Останні події безпеки/GeoBlock».</li>
				<li><strong>Кнопка «Аналізувати зараз»</strong> — запускає OpenAI-аналіз останніх ~100 рядків:
					<ul>
						<li>Ключ береться з опції <code>crit_openai_key</code>, константи <code>CRIT_OPENAI_KEY</code> або <code>$GLOBALS['CL_AI_KEY']</code>.</li>
						<li>Перед відправкою застосовується скрабер <code>crit_ai_scrub_lines()</code> (редакція токенів, cookie, email, IP, хешів).</li>
						<li>HTTP-фейловер: cURL → WP streams → raw socket; CA-бандл з <code>wp-includes/certificates/ca-bundle.crt</code> (якщо є).</li>
					</ul>
				</li>
				<li><strong>Продуктивність</strong> — <code>crit_ai_generate_insights()</code> кешує розрахунок на 60с; читання хвоста файлу ~512КБ.</li>
			</ul>
			<p><span class="crit-kbd">Esc</span> — закрити; клік по затемненню — теж закриє.</p>
		</div>
	</div>
</div>
<?php

	$badge_color = '#2d7';
	if (!empty($ai['risk']['code']) && $ai['risk']['code'] === 'amber') $badge_color = '#f7a600';
	if (!empty($ai['risk']['code']) && $ai['risk']['code'] === 'red')   $badge_color = '#e11';

	echo '<div style="padding:12px 14px;border:1px solid #ddd;border-left:6px solid '.$badge_color.';background:#fff;margin-bottom:14px;border-radius:6px;">';
	$label = is_array($ai['risk']) && isset($ai['risk']['label']) ? $ai['risk']['label'] : '—';
	echo '<div style="font-size:16px;margin-bottom:6px;"><strong>Загальний стан системи:</strong> ' . esc_html($label) . '</div>';

	$reasons = (is_array($ai['risk']) && !empty($ai['risk']['reasons'])) ? $ai['risk']['reasons'] : [];
	if ($reasons) { echo '<ul style="margin:6px 0 0 18px;">'; foreach ($reasons as $r) echo '<li>' . esc_html($r) . '</li>'; echo '</ul>'; }
	else { echo '<p style="margin:6px 0 0;">Причин не виявлено.</p>'; }
	echo '</div>';

	$s = is_array($ai['stats']) ? $ai['stats'] : [];
	$last24 = isset($s['last24']) && is_array($s['last24']) ? $s['last24'] : ['errors'=>0,'warnings'=>0,'security'=>0,'geoblock'=>0,'logins'=>0,'total'=>0];

	$card = function($title, $value) {
		return '<div style="min-width:120px;background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:10px 12px;">
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

	$dt = isset($ai['details']) && is_array($ai['details']) ? $ai['details'] : [];

	// === Стилі та місця під компактні графіки ===
	echo '<style>
	  #crit-analytics-grid{
	    display:grid;
	    grid-template-columns:repeat(auto-fit,minmax(280px,1fr));
	    gap:12px; align-items:start; width:100%;
	    max-width:100%;
	  }
	  .crit-card{
	    background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:10px 12px;
	    position:relative; min-width:0; overflow:hidden; contain:layout;
	  }
	  .crit-card h3{margin:0 0 8px;font-size:14px;font-weight:600}
	  .crit-canvas{display:block;width:100% !important;height:140px !important}
	  .crit-canvas.line{height:120px !important}
	</style>';

	echo '<div id="crit-analytics-grid">
	  <div class="crit-card"><h3>Події по днях</h3><canvas id="critByDay" class="crit-canvas line"></canvas></div>
	  <div class="crit-card"><h3>Топ країн (Geo)</h3><canvas id="critByCountry" class="crit-canvas"></canvas></div>
	  <div class="crit-card"><h3>Топ IP</h3><canvas id="critByIp" class="crit-canvas"></canvas></div>
	</div>';

	// Мікро-гістограма годин
	if (!empty($dt['hours_hist']) && is_array($dt['hours_hist'])) {
		$hist = $dt['hours_hist'];
		ksort($hist);
		$maxv = max($hist);
		echo '<div style="margin:14px 0;background:#fff;border:1px solid #e5e7eb;border-radius:8px;min-width:0;overflow:hidden;">';
		echo '<div style="padding:10px 12px;border-bottom:1px solid #eee;font-weight:600;">Розподіл за годинами</div>';
		echo '<div style="padding:10px 12px">';
		foreach ($hist as $hour => $val) {
			$w = $maxv ? max(2, (int)round(($val/$maxv)*100)) : 2;
			echo '<div style="display:flex;align-items:center;gap:8px;margin:4px 0;min-width:0;">'
			   . '<div style="width:120px;color:#666;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">'.esc_html($hour).'</div>'
			   . '<div style="flex:1;background:#f1f5f9;border-radius:4px;overflow:hidden;"><div style="height:8px;width:'.$w.'%;background:#3b82f6;"></div></div>'
			   . '<div style="width:36px;text-align:right;font-size:12px;color:#555;">'.intval($val).'</div>'
			   . '</div>';
		}
		echo '</div></div>';
	}

	$last_err = $dt['last_errors'] ?? [];
	$last_sec = $dt['last_security'] ?? [];
	if ($last_err) {
		echo '<div style="margin:14px 0;background:#fff;border:1px solid #e5e7eb;border-radius:8px;min-width:0;overflow:auto;">';
		echo '<div style="padding:10px 12px;border-bottom:1px solid #eee;font-weight:600;">Останні помилки</div>';
		echo '<pre style="margin:0;padding:10px 12px;max-height:220px;overflow:auto;white-space:pre-wrap;">';
		foreach ($last_err as $l) echo esc_html($l)."\n";
		echo '</pre></div>';
	}
	if ($last_sec) {
		echo '<div style="margin:14px 0;background:#fff;border:1px solid #e5e7eb;border-radius:8px;min-width:0;overflow:auto;">';
		echo '<div style="padding:10px 12px;border-bottom:1px solid #eee;font-weight:600;">Останні події безпеки / GeoBlock</div>';
		echo '<pre style="margin:0;padding:10px 12px;max-height:220px;overflow:auto;white-space:pre-wrap;">';
		foreach ($last_sec as $l) echo esc_html($l)."\n";
		echo '</pre></div>';
	}

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
	echo '<hr><p style="color:#777;">Цей модуль використовує API OpenAI (GPT-4o-mini або GPT-5) для генерації короткого аналізу логів.</p>';
	?>
<script>
// === INFO MODAL (AI page) ===
(function($){
	var $modal    = $('#crit-ai-info-modal');
	var $dialog   = $modal.find('.crit-modal__dialog');
	var $openBtn  = $('#crit-ai-info-open');
	var $closeBtn = $('#crit-ai-info-close');
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
