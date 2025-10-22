<?php
/**
 * Critical Event Logger — helper module
 * Copyright © 2025 Казмірчук Андрій
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */
if (!defined('ABSPATH')) exit;

function crit_sanitize_enabled() {
	$on = get_option('crit_log_sanitize', '0');
	return $on === '1' || $on === 1;
}

function crit_sanitize_text($text) {
	if (!crit_sanitize_enabled() || !is_string($text) || $text === '') return $text;

	// Email
	$text = preg_replace_callback(
		'~\b([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b~u',
		'crit_mask_email_cb',
		$text
	);

	// IPv6 у вільному тексті
	$text = preg_replace_callback(
		'~\b([A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{0,4}){2,7})\b~',
		'crit_mask_ipv6_cb',
		$text
	);

	// Телефони
	$text = preg_replace_callback(
		'~(?<!\w)(\+?\s*\d[\d\-\s\(\)]{8,}\d)(?!\w)~',
		'crit_mask_phone_cb',
		$text
	);

	// ВАЖЛИВО: IPv4 тут НЕ маскуємо, щоб не ламати структурні IP поза цим викликом

	return apply_filters('crit_sanitize_text', $text);
}

/**
 * Маскує лише user/message у стандартному рядку:
 * [Y-m-d H:i:s][IP][user][LEVEL] message
 * Якщо формат не збігся — маскує весь текст як fallback.
 */
function crit_sanitize_log_line_structured($line) {
	if (!crit_sanitize_enabled()) return $line;
	if (!is_string($line) || $line === '') return $line;

	if (preg_match('/^\[([0-9\- :]+)\]\[([^\]]+)\]\[([^\]]*)\]\[([^\]]+)\]\s?(.*)$/u', $line, $m)) {
		$time = $m[1];
		$ip   = $m[2];            // НЕ чіпаємо
		$user = $m[3];            // маскуємо (email/phone у імені)
		$lvl  = $m[4];
		$msg  = $m[5];            // маскуємо (email/phone/IPv6 у тексті)

		$userMasked = $user !== '' ? crit_sanitize_text($user) : '';
		$msgMasked  = crit_sanitize_text($msg);

		return '['.$time.']['.$ip.']['.$userMasked.']['.$lvl.'] '.$msgMasked;
	}

	// fallback — на всякий
	return crit_sanitize_text($line);
}

/* ===== helpers ===== */

function crit_mask_email_cb($m) {
	$local = $m[1]; $dom = $m[2];
	$l0 = mb_substr($local, 0, 1, 'UTF-8');
	$localMasked = $l0 . '***';
	$parts = explode('.', $dom);
	if (count($parts) >= 2) {
		$first = $parts[0]; $tld = array_pop($parts);
		$f0 = mb_substr($first, 0, 1, 'UTF-8');
		$domMasked = $f0 . '****.' . $tld;
	} else {
		$domMasked = '****.' . $dom;
	}
	return $localMasked . '@' . $domMasked;
}

function crit_mask_ipv6_cb($m) {
	$seg = explode(':', $m[1]);
	if (count($seg) < 3) return 'xxxx';
	return $seg[0] . '::xxxx::' . end($seg);
}

function crit_mask_phone_cb($m) {
	$raw = $m[1];
	$digits = preg_replace('~\D+~', '', $raw);
	$len = strlen($digits);
	if ($len < 10) return $raw;
	$keepLeft  = ($len >= 12) ? 4 : 3;
	$keepRight = 2;
	$left  = substr($digits, 0, $keepLeft);
	$right = substr($digits, -$keepRight);
	return '+' . $left . str_repeat('*', max(0, $len - $keepLeft - $keepRight)) . $right;
}
