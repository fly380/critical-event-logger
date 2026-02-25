<?php
/**
 * Critical Event Logger — helper module
 * Copyright © 2025 Казмірчук Андрій
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if (!defined('ABSPATH')) exit;

if (!defined('CRIT_ABUSEIPDB_KEY')) define('CRIT_ABUSEIPDB_KEY', '');
if (!defined('CRIT_VIRUSTOTAL_KEY')) define('CRIT_VIRUSTOTAL_KEY', '');
// Залишимо визначення, але ключ більше ніде не використовується:
// if (!defined('CRIT_CROWDSEC_KEY')) define('CRIT_CROWDSEC_KEY', '');
if (!defined('CRIT_INTEL_CACHE_TTL')) define('CRIT_INTEL_CACHE_TTL', 12 * HOUR_IN_SECONDS);
if (!defined('CRIT_IP_THRESHOLD')) define('CRIT_IP_THRESHOLD', 8);

// ---- Єдині геттери ключів (пріоритет: БД -> wp-config.php) ----
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

// Ключі читаються безпосередньо у функціях через crit_get_option_or_const()
// Глобальні змінні прибрано — щоб уникнути залежності від порядку підключення файлів

/**
 * Отримати IP, що часто з’являються у логах (для аналітики)
 */
function crit_get_suspicious_ips($log_file) {
	if (!file_exists($log_file)) return array();
	$lines = file($log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
	$counts = array();
	foreach ($lines as $line) {
		if (preg_match('/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', $line, $m)) {
			$ip = $m[1];
			$counts[$ip] = isset($counts[$ip]) ? $counts[$ip] + 1 : 1;
		}
	}
	arsort($counts);
	return array_filter($counts, function($c) {
		return $c >= CRIT_IP_THRESHOLD;
	});
}

/**
 * Перевірка IP через AbuseIPDB, VirusTotal, Spamhaus.
 * (CrowdSec повністю прибрано)
 */
function crit_check_ip_intel($ip) {
	$cache_key = 'crit_intel_' . md5($ip);
	if ($cached = get_transient($cache_key)) return $cached;

	$abuse_key = crit_get_option_or_const('CRIT_ABUSEIPDB_KEY', 'crit_abuseipdb_key');
	$vt_key    = crit_get_option_or_const('CRIT_VIRUSTOTAL_KEY', 'crit_virustotal_key');

	$result = array(
		'ip'           => $ip,
		'abuseipdb'    => 0,
		'virustotal'   => 0,
		'spamhaus'     => false,
		'score'        => 0,
		'is_malicious' => false,
		'source'       => ''
	);

	$sources = [];

	// === AbuseIPDB ===
	if ($abuse_key !== '') {
		$r = wp_remote_get("https://api.abuseipdb.com/api/v2/check?ipAddress=$ip", array(
			'headers' => array(
				'Key'        => $abuse_key,
				'Accept'     => 'application/json',
				'User-Agent' => 'CriticalLogger/2.1',
				'Referer'    => get_site_url()
			),
			'timeout' => 10,
		));
		if (!is_wp_error($r)) {
			$d = json_decode(wp_remote_retrieve_body($r), true);
			if (!empty($d['data']['abuseConfidenceScore'])) {
				$score = intval($d['data']['abuseConfidenceScore']);
				$result['abuseipdb'] = $score;
				$sources[] = 'AbuseIPDB (' . $score . '%)';
				if ($score >= 60) $result['is_malicious'] = true;
			}
		}
	}

	// === VirusTotal ===
	if ($vt_key !== '') {
		$r = wp_remote_get("https://www.virustotal.com/api/v3/ip_addresses/$ip", array(
			'headers' => array(
				'x-apikey'   => $vt_key,
				'User-Agent' => 'CriticalLogger/2.1 (WordPress; PHP ' . PHP_VERSION . ')',
				'Accept'     => 'application/json'
			),
			'timeout'     => 15,
			'redirection' => 3,
		));
		if (!is_wp_error($r)) {
			$d = json_decode(wp_remote_retrieve_body($r), true);
			$positives = 0;
			$attrs = $d['data']['attributes'] ?? [];

			if (!empty($attrs['last_analysis_results'])) {
				foreach ($attrs['last_analysis_results'] as $res) {
					$cat = strtolower($res['category'] ?? '');
					if ($cat === 'malicious' || $cat === 'suspicious') $positives++;
				}
			} elseif (!empty($attrs['reputation']) && $attrs['reputation'] < 0) {
				$positives = abs((int) $attrs['reputation']);
			} elseif (!empty($attrs['tags'])) {
				foreach ($attrs['tags'] as $tag) {
					if (preg_match('/malicious|botnet|scanner|spam/i', $tag)) {
						$positives++;
					}
				}
			}

			$result['virustotal'] = $positives;
			if ($positives > 0) {
				$sources[] = 'VirusTotal (' . $positives . ' детектів)';
				$result['is_malicious'] = true;
			}
		}
	}

	// === Spamhaus DNSBL (лише IPv4, з кешем і захистом від зависання) ===
	if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
		$spam_key = 'crit_spamhaus_' . md5($ip);
		$spam_cached = get_transient($spam_key);

		if ($spam_cached !== false) {
			// Використовуємо кешований результат (true/false)
			$in_spamhaus = (bool) $spam_cached;
		} else {
			$rev = implode('.', array_reverse(explode('.', $ip))) . '.zen.spamhaus.org';
			// gethostbyname повертає IP якщо знайдено, або той самий рядок якщо ні
			// Значно швидший за checkdnsrr, вбудований таймаут ОС (~5с)
			$lookup     = @gethostbyname($rev);
			$in_spamhaus = ($lookup !== $rev && filter_var($lookup, FILTER_VALIDATE_IP));
			// Кешуємо: позитив — 6 год, негатив — 1 год
			set_transient($spam_key, $in_spamhaus ? 1 : 0, $in_spamhaus ? 6 * HOUR_IN_SECONDS : HOUR_IN_SECONDS);
		}

		if ($in_spamhaus) {
			$result['spamhaus'] = true;
			$sources[]          = 'Spamhaus';
			$result['is_malicious'] = true;
		}
	}

	// === Підсумковий SCORE ===
	$total_score = 0;
	if (!empty($result['abuseipdb'])) $total_score += (int) $result['abuseipdb'];
	if (!empty($result['virustotal'])) $total_score += ((int) $result['virustotal']) * 10;
	if (!empty($result['spamhaus']))   $total_score += 30;

	$result['score']  = min($total_score, 150);
	$result['source'] = $sources ? implode(', ', $sources) : '-';

	if ($result['score'] >= 80 || count($sources) > 1) {
		$result['is_malicious'] = true;
	}

	set_transient($cache_key, $result, CRIT_INTEL_CACHE_TTL);
	return $result;
}

/**
 * Обгортка для використання в інших файлах
 */
function crit_get_ip_score($ip, $force_update = false) {
	$cache_key = 'crit_intel_score_' . md5($ip);
	if (!$force_update && ($cached = get_transient($cache_key))) {
		return $cached;
	}
	$intel = crit_check_ip_intel($ip);
	$score = intval($intel['score']);
	$data = array(
		'score' => $score,
		'source' => $intel['source'],
		'is_malicious' => $intel['is_malicious']
	);
	set_transient($cache_key, $data, CRIT_INTEL_CACHE_TTL);
	return $data;
}

/**
 * Конвертація score → CSS клас
 */
function crit_score_to_class($score) {
	if ($score >= 60) return 'crit-ip-danger';
	if ($score >= 20) return 'crit-ip-warning';
	return 'crit-ip-safe';
}

/**
 * Підсвітка небезпечних IP у текстовому полі / логах
 */
function crit_highlight_ips_in_log_text($text) {
	$ips = crit_get_suspicious_ips(crit_log_file());
	foreach ($ips as $ip => $cnt) {
		$intel = crit_get_ip_score($ip);
		if ($intel['is_malicious']) {
			$text = preg_replace(
				'/\b' . preg_quote($ip, '/') . '\b/',
				'<span class="crit-ip-danger">' . esc_html($ip) . '</span>',
				$text
			);
		}
	}
	return $text;
}

/**
 * Вивід таблиці аналітики підозрілих IP у адмінці
 */
function crit_render_intel_block() {
	if (!current_user_can('manage_options')) return;
	$ips = crit_get_suspicious_ips(crit_log_file());

	echo '<div class="crit-intel-block" style="margin-top:20px;">';
	echo '<h3>Підозрілі IP</h3>';
	echo '<table class="widefat"><thead><tr>
		<th>IP</th><th>Кількість</th><th>Score</th><th>Джерела</th><th>Стан</th>
	</tr></thead><tbody>';

	foreach ($ips as $ip => $cnt) {
		$intel = crit_get_ip_score($ip);
		$class = crit_score_to_class($intel['score']);
		$row_style = $class === 'crit-ip-danger' ? 'style="background:#ffd7d7;"' :
			($class === 'crit-ip-warning' ? 'style="background:#fff4cc;"' : '');

		echo '<tr ' . $row_style . '>';
		echo '<td>' . esc_html($ip) . '</td>';
		echo '<td>' . (int) $cnt . '</td>';
		echo '<td>' . (int) $intel['score'] . '</td>';
		echo '<td>' . esc_html($intel['source'] ?: '-') . '</td>';
		echo '<td>' . ($intel['is_malicious'] ? '❌ Підозрілий' : '✅ Безпечний') . '</td>';
		echo '</tr>';
	}

	echo '</tbody></table></div>';
}