<?php
/**
 * Critical Event Logger — helper module
 * Copyright © 2025 Казмірчук Андрій
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */
if (!defined('ABSPATH')) exit;

/** =========================
 *  Helpers (із ґардами)
 *  ========================= */
/** Перелік резервних копій .htaccess (новіші — першими) */
if (!function_exists('crit_ht_list_backups')) {
	function crit_ht_list_backups(string $path): array {
		$dir = dirname($path);
		$bn  = basename($path); // очікуємо ".htaccess"
		$glob = glob($dir . '/' . $bn . '.bak-*') ?: [];
		$out = [];
		foreach ($glob as $f) {
			$base = basename($f);
			$ts = null;
			if (preg_match('/\.bak-(\d{8}-\d{6})$/', $base, $m)) {
				$dt = \DateTime::createFromFormat('Ymd-His', $m[1]);
				if ($dt) $ts = $dt->getTimestamp();
			}
			if ($ts === null) $ts = @filemtime($f) ?: 0;
			$out[] = [
				'basename' => $base,
				'path'     => $f,
				'ts'       => $ts,
				'date'     => gmdate('Y-m-d H:i:s', $ts),
				'size'     => @filesize($f) ?: 0,
			];
		}
		usort($out, static function($a,$b){ return $b['ts'] <=> $a['ts']; });
		return $out;
	}
}

/** Тримати не більше $keep резервних копій (видалити старші) */
if (!function_exists('crit_ht_rotate_backups')) {
	function crit_ht_rotate_backups(string $path, int $keep = 3): void {
		$list = crit_ht_list_backups($path);
		if (count($list) <= $keep) return;
		$to_delete = array_slice($list, $keep); // усе після перших $keep
		foreach ($to_delete as $bk) {
			@unlink($bk['path']); // best-effort
		}
	}
}

/** Шлях до .htaccess */
if (!function_exists('crit_ht_get_path')) {
	function crit_ht_get_path(): string {
		require_once ABSPATH . 'wp-admin/includes/file.php';
		if (function_exists('get_home_path')) {
			return trailingslashit(get_home_path()) . '.htaccess';
		}
		return ABSPATH . '.htaccess';
	}
}

/** Визначити тип переносу рядків у вмісті */
if (!function_exists('crit_ht_detect_eol')) {
	function crit_ht_detect_eol(string $s): string {
		if (strpos($s, "\r\n") !== false) return "\r\n";
		if (strpos($s, "\r")   !== false) return "\r";
		return "\n";
	}
}

/** Чи схожий токен на IP/мережу/шаблон, що трапляється у .htaccess */
if (!function_exists('crit_ht_is_ipish')) {
	function crit_ht_is_ipish(string $t): bool {
		$t = trim($t);
		if ($t === '') return false;
		// IPv4 / IPv6
		if (filter_var($t, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) return true;
		// CIDR
		if (preg_match('~^[0-9a-f:]+/\d{1,3}$~i', $t)) return true;                 // IPv6/CIDR
		if (preg_match('~^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$~', $t)) return true;     // IPv4/CIDR
		// Урізані шаблони Apache 2.2
		if (preg_match('~^(?:\d{1,3}\.){1,3}\*?$~', $t)) return true;               // 123.* або 10.0.0.*
		if (preg_match('~^(?:\d{1,3}\.){1,3}$~', $t)) return true;                  // 10.0.0.
		return false;
	}
}

/** Розбір .htaccess: збираємо всі заблоковані IP з Deny/Require not ip */
if (!function_exists('crit_ht_parse_blocked')) {
	function crit_ht_parse_blocked(string $content): array {
		$lines = preg_split("/\r\n|\n|\r/", $content);
		$res   = [];   // token => ['count'=>N,'places'=>[['line'=>i,'type'=>'deny'|'require_not','raw'=>line]]]

		foreach ($lines as $i => $ln) {
			$line = trim($ln);
			if ($line === '' || (isset($line[0]) && $line[0] === '#')) continue;

			// Apache 2.2: Deny from <tokens...>
			if (preg_match('~^Deny\s+from\s+(.+)$~i', $line, $m)) {
				$tokens = preg_split('~\s+~', trim($m[1]));
				foreach ($tokens as $tok) {
					if (!crit_ht_is_ipish($tok)) continue;
					if (!isset($res[$tok])) $res[$tok] = ['count'=>0,'places'=>[]];
					$res[$tok]['count']++;
					$res[$tok]['places'][] = ['line'=>$i,'type'=>'deny','raw'=>$ln];
				}
				continue;
			}

			// Apache 2.4: Require not ip <tokens...>
			if (preg_match('~^Require\s+not\s+ip\s+(.+)$~i', $line, $m)) {
				$tokens = preg_split('~\s+~', trim($m[1]));
				foreach ($tokens as $tok) {
					if (!crit_ht_is_ipish($tok)) continue;
					if (!isset($res[$tok])) $res[$tok] = ['count'=>0,'places'=>[]];
					$res[$tok]['count']++;
					$res[$tok]['places'][] = ['line'=>$i,'type'=>'require_not','raw'=>$ln];
				}
				continue;
			}
		}
		return $res;
	}
}

/** =========================
 *  Видалення токена (із scope)
 *  ========================= */

/**
 * Прибрати токен з ОДНОГО рядка (мінімальна зміна форматування)
 * $onlyType: null|'deny'|'require_not'
 */
if (!function_exists('crit_ht_strip_token_from_line')) {
	function crit_ht_strip_token_from_line(string $line, string $token, bool &$changed, ?string $onlyType = null): string {
		$changed = false;

		// Apache 2.2: Deny from ...
		if (preg_match('~^(\s*Deny\s+from\s+)(.+)$~i', $line, $m)) {
			if ($onlyType && $onlyType !== 'deny') return $line;
			$prefix  = $m[1];
			$rest    = $m[2];
			$pattern = '/(?<!\S)'.preg_quote($token,'/').'(?!\S)/'; // ціле слово
			$newRest = preg_replace($pattern, '', $rest, -1, $cnt);
			if ($cnt > 0) {
				$changed = true;
				$newRest = preg_replace('/\s{2,}/', ' ', $newRest);
				$newRest = rtrim($newRest);
				return $newRest === '' ? '' : ($prefix . $newRest);
			}
			return $line;
		}

		// Apache 2.4: Require not ip ...
		if (preg_match('~^(\s*Require\s+not\s+ip\s+)(.+)$~i', $line, $m)) {
			if ($onlyType && $onlyType !== 'require_not') return $line;
			$prefix  = $m[1];
			$rest    = $m[2];
			$pattern = '/(?<!\S)'.preg_quote($token,'/').'(?!\S)/';
			$newRest = preg_replace($pattern, '', $rest, -1, $cnt);
			if ($cnt > 0) {
				$changed = true;
				$newRest = preg_replace('/\s{2,}/', ' ', $newRest);
				$newRest = rtrim($newRest);
				return $newRest === '' ? '' : ($prefix . $newRest);
			}
			return $line;
		}

		return $line;
	}
}

/**
 * Видалити токен з контенту (зберігаючи оригінальні переноси рядків)
 * $onlyType: null|'deny'|'require_not'
 */
if (!function_exists('crit_ht_remove_token_from_content')) {
	function crit_ht_remove_token_from_content(string $content, string $token, ?string $onlyType = null): string {
		$eol   = crit_ht_detect_eol($content);
		$lines = preg_split("/\r\n|\n|\r/", $content);
		$changedAny = false;

		foreach ($lines as $i => $ln) {
			$changed = false;
			$newLn   = crit_ht_strip_token_from_line($ln, $token, $changed, $onlyType);
			if ($changed) {
				$changedAny = true;
				$lines[$i]  = $newLn; // зберігаємо структуру (порожній рядок теж)
			}
		}
		return $changedAny ? implode($eol, $lines) : $content;
	}
}

/** Створити резервну копію .htaccess із timestamp-суфіксом (+ротація до 3 шт.) */
if (!function_exists('crit_ht_backup_file')) {
	function crit_ht_backup_file(string $path): bool {
		$dir = dirname($path); $bn = basename($path);
		$bak = $dir . '/' . $bn . '.bak-' . gmdate('Ymd-His');
		$ok  = @copy($path, $bak) !== false;
		if ($ok) {
			// Після успішного бекапу — підріжемо зайві
			if (function_exists('crit_ht_rotate_backups')) {
				crit_ht_rotate_backups($path, 3);
			}
		}
		return $ok;
	}
}


/**
 * Видалити токен у файлі (із резервною копією)
 * $onlyType: null|'deny'|'require_not'
 */
if (!function_exists('crit_ht_remove_token_in_file')) {
	function crit_ht_remove_token_in_file(string $path, string $token, &$err = null, ?string $onlyType = null): bool {
		$err = null;
		if (!file_exists($path)) { $err = 'Файл .htaccess не знайдено.'; return false; }
		if (!is_readable($path)) { $err = 'Файл .htaccess недоступний для читання.'; return false; }
		if (!is_writable($path)) { $err = 'Файл .htaccess недоступний для запису.'; return false; }

		$raw = @file_get_contents($path);
		if ($raw === false) { $err = 'Не вдалося прочитати .htaccess.'; return false; }

		$new = crit_ht_remove_token_from_content($raw, $token, $onlyType);
		if ($new === $raw) { $err = 'Такий запис не знайдено (може вже видалений).'; return false; }

		crit_ht_backup_file($path); // best-effort
		$ok = @file_put_contents($path, $new, LOCK_EX);
		if ($ok === false) { $err = 'Не вдалося записати оновлений .htaccess.'; return false; }
		return true;
	}
}

/**
 * Dry-run: повертає новий вміст + хунки змін (рядок/було/стало)
 * $onlyType: null|'deny'|'require_not'
 */
if (!function_exists('crit_ht_preview_remove')) {
	function crit_ht_preview_remove(string $content, string $token, ?string $onlyType = null): array {
		$eol   = crit_ht_detect_eol($content);
		$lines = preg_split("/\r\n|\n|\r/", $content);
		$changedAny = false;
		$hunks = [];

		foreach ($lines as $i => $ln) {
			$changed = false;
			$newLn   = crit_ht_strip_token_from_line($ln, $token, $changed, $onlyType);
			if ($changed) {
				$changedAny = true;
				$hunks[] = ['line' => $i+1, 'old' => $ln, 'new' => $newLn];
				$lines[$i] = $newLn;
			}
		}

		return [
			'changed' => $changedAny,
			'new'     => implode($eol, $lines),
			'hunks'   => $hunks,
		];
	}
}

/** =========================
 *  Нормалізація
 *  ========================= */

if (!function_exists('crit_ht_norm_split_tokens')) {
	function crit_ht_norm_split_tokens(string $s): array {
		$raw = preg_split('~\s+~', trim($s)) ?: [];
		$out = [];
		foreach ($raw as $t) {
			$t = trim($t);
			if ($t === '') continue;
			if (!crit_ht_is_ipish($t)) continue;
			if (strpos($t, ':') !== false) $t = strtolower($t); // IPv6 в нижньому регістрі
			$out[] = $t;
		}
		return $out;
	}
}
if (!function_exists('crit_ht_norm_unique_sort')) {
	function crit_ht_norm_unique_sort(array $tokens): array {
		$uniq = [];
		foreach ($tokens as $t) { $uniq[strtolower($t)] = $t; }
		$tokens = array_values($uniq);
		usort($tokens, 'strnatcasecmp'); // «людське» сортування
		return $tokens;
	}
}

/**
 * Нормалізація правил у контенті:
 * - зливає СУМІЖНІ "Deny from …" в один рядок;
 * - зливає СУМІЖНІ "Require not ip …" в один рядок;
 * - прибирає дублікати токенів, сортує;
 * - не чіпає інші рядки та порожні рядки (щоб не було «шуму» в diff).
 */
if (!function_exists('crit_ht_normalize_rules_in_content')) {
	function crit_ht_normalize_rules_in_content(string $content): array {
		$eol   = crit_ht_detect_eol($content);
		$lines = preg_split("/\r\n|\n|\r/", $content);
		$n = count($lines);
		$changed = false;

		$deny_total_before = 0; $deny_total_after = 0;
		$req_total_before  = 0; $req_total_after  = 0;

		for ($i=0; $i<$n; $i++) {
			$ln = $lines[$i];

			// === Блок Deny from (Apache 2.2)
			if (preg_match('~^(\s*)Deny(\s+)from(\s+)(.+?)\s*$~i', $ln, $m)) {
				$indent = $m[1];
				$tokens = crit_ht_norm_split_tokens($m[4]);
				$deny_total_before += count($tokens);

				$j = $i + 1;
				while ($j < $n && preg_match('~^\s*Deny\s+from\s+(.+?)\s*$~i', $lines[$j], $mm)) {
					$more = crit_ht_norm_split_tokens($mm[1]);
					$deny_total_before += count($more);
					$tokens = array_merge($tokens, $more);
					$lines[$j] = ''; // поглинаємо — лише очищаємо рядок, не видаляємо
					$j++;
				}
				$tokens = crit_ht_norm_unique_sort($tokens);
				$deny_total_after += count($tokens);

				$newLine = $tokens ? ($indent . 'Deny from ' . implode(' ', $tokens)) : '';
				if ($newLine !== $ln) { $changed = true; }
				$lines[$i] = $newLine;

				$i = $j - 1; // перескочити опрацьовані
				continue;
			}

			// === Блок Require not ip (Apache 2.4)
			if (preg_match('~^(\s*)Require(\s+)not(\s+)ip(\s+)(.+?)\s*$~i', $ln, $m)) {
				$indent = $m[1];
				$tokens = crit_ht_norm_split_tokens($m[5]);
				$req_total_before += count($tokens);

				$j = $i + 1;
				while ($j < $n && preg_match('~^\s*Require\s+not\s+ip\s+(.+?)\s*$~i', $lines[$j], $mm)) {
					$more = crit_ht_norm_split_tokens($mm[1]);
					$req_total_before += count($more);
					$tokens = array_merge($tokens, $more);
					$lines[$j] = '';
					$j++;
				}
				$tokens = crit_ht_norm_unique_sort($tokens);
				$req_total_after += count($tokens);

				$newLine = $tokens ? ($indent . 'Require not ip ' . implode(' ', $tokens)) : '';
				if ($newLine !== $ln) { $changed = true; }
				$lines[$i] = $newLine;

				$i = $j - 1;
				continue;
			}
		}

		// Зберігаємо структуру (включно з порожніми рядками)
		$new = implode($eol, $lines);

		return [
			'changed' => $changed,
			'new'     => $new,
			'stats'   => [
				'deny_before' => $deny_total_before,
				'deny_after'  => $deny_total_after,
				'req_before'  => $req_total_before,
				'req_after'   => $req_total_after,
			],
		];
	}
}

/** Рендер «тихого» diff — показуємо лише реально змінені рядки з номерами */
// Замінити попередню версію цієї функції
if (!function_exists('crit_ht_render_unified_diff')) {
	function crit_ht_render_unified_diff(string $old, string $new, string $highlight_token = ''): string {
		$eol = crit_ht_detect_eol($old);
		$A = preg_split("/\r\n|\n|\r/", $old);
		$B = preg_split("/\r\n|\n|\r/", $new);
		$max = max(count($A), count($B));
		$html_lines = [];

		// Підготовимо патерн для підсвітки (ціле «слово» між пробілами)
		$pattern = $highlight_token !== ''
			? '/(?<!\S)(' . preg_quote($highlight_token, '/') . ')(?!\S)/i'
			: null;

		for ($i = 0; $i < $max; $i++) {
			$la = $A[$i] ?? '';
			$lb = $B[$i] ?? '';
			if ($la === $lb) continue;

			$html_lines[] = '<span class="crit-ln">'.esc_html('L'.($i+1).':').'</span>';

			if ($la !== '') {
				// Екрануємо по частинах, щоб підсвітити лише токен
				$old_html = '';
				if ($pattern) {
					$parts = preg_split($pattern, $la, -1, PREG_SPLIT_DELIM_CAPTURE);
					foreach ($parts as $idx => $part) {
						if ($idx % 2 === 1) {
							$old_html .= '<span class="crit-tok-del">'.esc_html($part).'</span>';
						} else {
							$old_html .= esc_html($part);
						}
					}
				} else {
					$old_html = esc_html($la);
				}
				$html_lines[] = '<span class="crit-old">- '.$old_html.'</span>';
			}

			if ($lb !== '') {
				$html_lines[] = '<span class="crit-new">+ '.esc_html($lb).'</span>';
			}

			$html_lines[] = ''; // порожній рядок між хунками
		}

		if (!$html_lines) {
			$html_lines[] = esc_html('— змін не виявлено —');
		}

		return '<pre class="crit-diff" style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:10px;white-space:pre-wrap;overflow:auto;max-height:60vh;">'
			 . implode($eol, $html_lines)
			 . '</pre>';
	}
}

/** =========================
 *  Адмін-сторінка (v2)
 *  ========================= */

function crit_ht_blocklist_admin_page_v2() {
	if (!current_user_can('manage_options')) return;

	$path   = crit_ht_get_path();
	$notice = '';

	/* 1) Підтверджене видалення токена (після dry-run або одразу) */
	if (isset($_POST['crit_ht_confirm_delete']) && isset($_POST['token'])) {
		check_admin_referer('crit_ht_confirm_delete');
		$tok   = trim(rawurldecode((string) wp_unslash($_POST['token'])));
		$scope = isset($_POST['scope']) ? sanitize_text_field((string) $_POST['scope']) : 'all';
		$onlyType = ($scope === 'deny' ? 'deny' : ($scope === 'require_not' ? 'require_not' : null));

		if (!crit_ht_is_ipish($tok)) {
			$notice = '<div class="notice notice-error"><p>❌ Невалідний токен.</p></div>';
		} else {
			$err = null;
			if (crit_ht_remove_token_in_file($path, $tok, $err, $onlyType)) {
				$where = $onlyType ? ($onlyType === 'deny' ? ' (лише Deny from)' : ' (лише Require not ip)') : '';
				$notice = '<div class="notice notice-success"><p>✅ Видалено <code>'.esc_html($tok).'</code>'.$where.' із .htaccess.</p></div>';
			} else {
				$notice = '<div class="notice notice-error"><p>❌ Не вдалося видалити: '.esc_html($err).'</p></div>';
			}
		}
	}

	/* 1b) Застосувати нормалізацію (після превʼю) */
	if (isset($_POST['crit_ht_apply_normalize'])) {
		check_admin_referer('crit_ht_apply_normalize');
		if (!file_exists($path) || !is_readable($path) || !is_writable($path)) {
			$notice = '<div class="notice notice-error"><p>❌ .htaccess недоступний для читання/запису.</p></div>';
		} else {
			$raw = (string) @file_get_contents($path);
			$res = crit_ht_normalize_rules_in_content($raw);
			if (empty($res['changed'])) {
				$notice = '<div class="notice notice-info"><p>ℹ️ Нема чого нормалізувати — змін не буде.</p></div>';
			} else {
				crit_ht_backup_file($path);
				$ok = @file_put_contents($path, $res['new'], LOCK_EX);
				if ($ok === false) {
					$notice = '<div class="notice notice-error"><p>❌ Не вдалося записати оновлений .htaccess.</p></div>';
				} else {
					$notice = '<div class="notice notice-success"><p>✅ Нормалізацію застосовано. Deny: '
						. intval($res['stats']['deny_before']).' → '.intval($res['stats']['deny_after'])
						. '; Require not ip: '.intval($res['stats']['req_before']).' → '.intval($res['stats']['req_after'])
						. '.</p></div>';
				}
			}
		}
	}
		/* 1c) Відновлення з резервної копії */
	if (isset($_POST['crit_ht_restore']) && isset($_POST['backup'])) {
		check_admin_referer('crit_ht_restore');
		$bn = basename((string) wp_unslash($_POST['backup'])); // лише basename
		// дозволяємо тільки наш шаблон .htaccess.bak-YYYYmmdd-HHMMSS
		if (!preg_match('/^\.htaccess\.bak-\d{8}-\d{6}$/', $bn)) {
			$notice = '<div class="notice notice-error"><p>❌ Невалідна резервна копія.</p></div>';
		} else {
			$dir = dirname($path);
			$full = $dir . '/' . $bn;
			if (!file_exists($full) || !is_readable($full)) {
				$notice = '<div class="notice notice-error"><p>❌ Обрана копія недоступна.</p></div>';
			} elseif (!is_writable($path)) {
				$notice = '<div class="notice notice-error"><p>❌ Файл .htaccess недоступний для запису.</p></div>';
			} else {
				// зробимо бекап поточного стану перед відновленням
				crit_ht_backup_file($path);
				$data = @file_get_contents($full);
				if ($data === false) {
					$notice = '<div class="notice notice-error"><p>❌ Не вдалося прочитати резервну копію.</p></div>';
				} elseif (@file_put_contents($path, $data, LOCK_EX) === false) {
					$notice = '<div class="notice notice-error"><p>❌ Не вдалося записати .htaccess.</p></div>';
				} else {
					// після відновлення теж збережемо ≤3 бекапи
					crit_ht_rotate_backups($path, 3);
					$notice = '<div class="notice notice-success"><p>✅ Відновлено з <code>'.esc_html($bn).'</code>.</p></div>';
				}
			}
		}
	}

	/* 2) Dry-run попередній перегляд видалення */
	$preview_token = '';
	$preview_diff  = '';
	$preview_stats = '';
	if (isset($_GET['crit_preview_ip'])) {
		$preview_token = trim(rawurldecode((string) wp_unslash($_GET['crit_preview_ip'])));
		$scope_q = isset($_GET['crit_scope']) ? sanitize_text_field((string) $_GET['crit_scope']) : 'all';
		$onlyType_q = ($scope_q === 'deny' ? 'deny' : ($scope_q === 'require_not' ? 'require_not' : null));

		if (!crit_ht_is_ipish($preview_token)) {
			$notice = '<div class="notice notice-error"><p>❌ Невалідний токен для попереднього перегляду.</p></div>';
			$preview_token = '';
		} else {
			if (!file_exists($path) || !is_readable($path)) {
				$notice = '<div class="notice notice-error"><p>❌ .htaccess недоступний для читання.</p></div>';
				$preview_token = '';
			} else {
				$raw = (string) @file_get_contents($path);
				$res = crit_ht_preview_remove($raw, $preview_token, $onlyType_q);
				if (empty($res['changed'])) {
					$notice = '<div class="notice notice-info"><p>ℹ️ Запис <code>'.esc_html($preview_token).'</code> не знайдено — змін не буде.</p></div>';
					$preview_token = '';
				} else {
					$preview_diff  = crit_ht_render_unified_diff($raw, $res['new'], $preview_token);
					$delta = strlen($res['new']) - strlen($raw);
					$preview_stats = '<p style="color:#667085">Зміна розміру файлу: '
						. ($delta>=0 ? '+' : '') . intval($delta) . ' байт.</p>';
				}
			}
		}
	}

	/* 2b) Dry-run попередній перегляд нормалізації */
	$norm_diff_html = '';
	$norm_stats_html = '';
	if (isset($_GET['crit_preview_normalize'])) {
		if (!file_exists($path) || !is_readable($path)) {
			$notice = '<div class="notice notice-error"><p>❌ .htaccess недоступний для читання.</p></div>';
		} else {
			$raw = (string) @file_get_contents($path);
			$res = crit_ht_normalize_rules_in_content($raw);
			if (empty($res['changed'])) {
				$notice = '<div class="notice notice-info"><p>ℹ️ Нема що зводити — файл уже нормалізований.</p></div>';
			} else {
				$norm_diff_html = crit_ht_render_unified_diff($raw, $res['new']);
				$norm_stats_html = '<p style="color:#667085">Deny: '
					. intval($res['stats']['deny_before']).' → '.intval($res['stats']['deny_after'])
					. '; Require not ip: '.intval($res['stats']['req_before']).' → '.intval($res['stats']['req_after']).'.</p>';
			}
		}
	}

	/* 3) Базові перевірки та парс */
	$content = '';
	if (file_exists($path) && is_readable($path)) {
		$content = (string) @file_get_contents($path);
	}
	$list = $content !== '' ? crit_ht_parse_blocked($content) : [];

	/* === UI === */
	echo '<div class="wrap"><h1>🔒 Заблоковані IP (.htaccess)</h1>';
	if ($notice) echo $notice;

	if (!file_exists($path)) {
		echo '<div class="notice notice-warning"><p>Файл <code>'.esc_html($path).'</code> не знайдено.</p></div></div>';
		return;
	}
	if (!is_readable($path)) {
		echo '<div class="notice notice-error"><p>Файл <code>'.esc_html($path).'</code> недоступний для читання.</p></div></div>';
		return;
	}

	echo '<p style="color:#667085">Підтримуються правила <code>Deny from …</code> (Apache 2.2) та <code>Require not ip …</code> (Apache 2.4). Є “dry-run” попередній перегляд, резервні копії та нормалізація суміжних правил без втручання в інші частини файла.</p>';

	// Стиль для кнопок/дій в один рядок
	echo '<style>
		.crit-actions{display:flex;gap:6px;align-items:center;flex-wrap:nowrap;white-space:nowrap}
		.crit-actions form{display:inline-flex;margin:0}
		.crit-actions .button{margin:0}
		.crit-inline-select{height:28px}
		.crit-actions{display:flex;gap:6px;align-items:center;flex-wrap:nowrap;white-space:nowrap}
		.crit-actions form{display:inline-flex;margin:0}
		.crit-actions .button{margin:0}
		/* Підсвітка видаленого токена у diff */
		.crit-diff .crit-tok-del{color:#b91c1c;background:#fee2e2;padding:0 2px;border-radius:3px}
	</style>';

		// === Резервні копії .htaccess ===
	$backups = crit_ht_list_backups($path);
	echo '<div class="card" style="padding:12px;margin-top:16px">';
	echo '<h2 style="margin:0 0 8px;">🗂 Резервні копії .htaccess</h2>';
	echo '<p style="color:#667085;margin:6px 0 10px">Система зберігає до <strong>3</strong> останніх копій і автоматично видаляє старші.</p>';

	if (empty($backups)) {
		echo '<div class="notice notice-info"><p>Копій ще немає.</p></div>';
	} else {
		echo '<form method="post" class="crit-actions" onsubmit="return confirm(\'Відновити .htaccess з обраної копії?\')">';
		wp_nonce_field('crit_ht_restore');
		echo '<select name="backup" class="crit-inline-select" style="min-width:320px">';
		foreach ($backups as $bk) {
			$label = sprintf('%s (UTC) — %0.1f KB', $bk['date'], max(0.1, $bk['size']/1024));
			echo '<option value="'.esc_attr($bk['basename']).'">'.esc_html($label).'</option>';
		}
		echo '</select> ';
		echo '<button type="submit" name="crit_ht_restore" class="button button-primary">↩︎ Відновити</button>';
		echo '</form>';
	}
	echo '</div>';
	// [NORMALIZE] Панель керування нормалізацією
	$preview_norm_url = esc_url(add_query_arg(['crit_preview_normalize' => 1]));
	echo '<div class="card" style="padding:12px;margin:12px 0;">
			<h2 style="margin:0 0 8px;">🧹 Злиття/нормалізація правил</h2>
			<p style="color:#667085;margin:6px 0 10px">
				Обʼєднуємо суміжні <code>Deny from …</code> та <code>Require not ip …</code> у один рядок,
				прибираємо дублікати, сортуємо токени. Порожні рядки та інші блоки залишаються без змін.
			</p>
			<div class="crit-actions">
				<a class="button" href="'.$preview_norm_url.'">👁 Попередній перегляд нормалізації</a>';

	if ($norm_diff_html !== '') {
		echo '<form method="post" onsubmit="return confirm(\'Застосувати нормалізацію до .htaccess?\')">';
		wp_nonce_field('crit_ht_apply_normalize');
		echo '<button type="submit" name="crit_ht_apply_normalize" class="button button-primary">✅ Застосувати</button>
			  <a class="button" href="'.esc_url(remove_query_arg('crit_preview_normalize')).'">Скасувати</a>
			</form>';
	}

	echo   '</div>';
	
	if ($norm_diff_html !== '') {
		echo '<div style="margin-top:10px">'.$norm_stats_html.$norm_diff_html.'</div>';
	}
	echo '</div>';

	// Блок dry-run превʼю видалення (якщо є)
	if ($preview_token !== '') {
		$scope_label = isset($_GET['crit_scope']) && $_GET['crit_scope']==='deny' ? ' (лише Deny from)' : (isset($_GET['crit_scope']) && $_GET['crit_scope']==='require_not' ? ' (лише Require not ip)' : '');
		echo '<h2 style="margin-top:12px">🧪 Попередній перегляд: <code>'.esc_html($preview_token).'</code>'.$scope_label.'</h2>';
		echo $preview_stats;
		echo $preview_diff;
		// підтвердження з тим самим scope
		$sel_all   = (!isset($_GET['crit_scope']) || $_GET['crit_scope']==='all') ? ' selected' : '';
		$sel_deny  = (isset($_GET['crit_scope']) && $_GET['crit_scope']==='deny') ? ' selected' : '';
		$sel_req   = (isset($_GET['crit_scope']) && $_GET['crit_scope']==='require_not') ? ' selected' : '';
		echo '<form method="post" style="margin-top:10px" onsubmit="return confirm(\'Підтвердити видалення '.esc_js($preview_token).'?\')">';
		wp_nonce_field('crit_ht_confirm_delete');
		echo '<input type="hidden" name="token" value="'.esc_attr(rawurlencode($preview_token)).'">';
		echo '<select name="scope" class="crit-inline-select">
				<option value="all"'.$sel_all.'>Усюди</option>
				<option value="deny"'.$sel_deny.'>Лише Deny from</option>
				<option value="require_not"'.$sel_req.'>Лише Require not ip</option>
			  </select> ';
		echo '<button type="submit" name="crit_ht_confirm_delete" class="button button-primary">✅ Підтвердити видалення</button> ';
		echo '<a class="button" href="'.esc_url(remove_query_arg(['crit_preview_ip','crit_scope'])).'">Скасувати</a>';
		echo '</form><hr>';
	}

	// Якщо нічого не знайдено
	if (!$list) {
		echo '<div class="notice notice-info"><p>У .htaccess не знайдено явних блокувань IP.</p></div>';
		echo '</div>';
		return;
	}

	// Таблиця токенів
	echo '<table class="widefat striped"><thead><tr>
			<th style="width:40%">IP / CIDR / шаблон</th>
			<th style="width:15%;text-align:right">Зустрічань</th>
			<th>Де знайдено</th>
			<th style="width:330px">Дія</th>
		</tr></thead><tbody>';

foreach ($list as $tok => $info) {
	$types = array_unique(array_map(function($p){ return $p['type']; }, $info['places']));
	$typeLabels = [];
	foreach ($types as $t) {
		$typeLabels[] = $t === 'deny' ? 'Apache 2.2 (Deny from)' : 'Apache 2.4 (Require not ip)';
	}
	$foundIn = implode(' • ', $typeLabels);

	$occurs_deny = in_array('deny', $types, true);
	$occurs_req  = in_array('require_not', $types, true);
	$has_both    = $occurs_deny && $occurs_req;

	// Побудуємо HTML дій
	$actions = '<div class="crit-actions">';

	if ($has_both) {
		// --- Є в обох типах: показуємо селект із 3 варіантами ---
		$actions .= '
		<form method="get">
			<input type="hidden" name="page" value="crit-htaccess-blocks">
			<input type="hidden" name="crit_preview_ip" value="'.esc_attr(rawurlencode($tok)).'">
			<select name="crit_scope" class="crit-inline-select">
				<option value="all">Усюди</option>
				<option value="deny">Лише Deny from</option>
				<option value="require_not">Лише Require not ip</option>
			</select>
			<button type="submit" class="button button-small">👁 Попередній перегляд</button>
		</form>

		<form method="post" onsubmit="return confirm(\''.esc_js("Підтвердити видалення $tok?").'\')">
			'.wp_nonce_field('crit_ht_confirm_delete', '_wpnonce', true, false).'
			<input type="hidden" name="token" value="'.esc_attr(rawurlencode($tok)).'">
			<select name="scope" class="crit-inline-select">
				<option value="all">Усюди</option>
				<option value="deny">Лише Deny from</option>
				<option value="require_not">Лише Require not ip</option>
			</select>
			<button type="submit" name="crit_ht_confirm_delete" class="button button-small button-secondary">🗑 Видалити</button>
		</form>';
	} else {
		// --- Є лише в одному типі: селект зайвий, передаємо scope приховано ---
		$single = $occurs_deny ? 'deny' : 'require_not';

		$actions .= '
		<form method="get">
			<input type="hidden" name="page" value="crit-htaccess-blocks">
			<input type="hidden" name="crit_preview_ip" value="'.esc_attr(rawurlencode($tok)).'">
			<input type="hidden" name="crit_scope" value="'.$single.'">
			<button type="submit" class="button button-small">👁 Попередній перегляд</button>
		</form>

		<form method="post" onsubmit="return confirm(\''.esc_js("Підтвердити видалення $tok?").'\')">
			'.wp_nonce_field('crit_ht_confirm_delete', '_wpnonce', true, false).'
			<input type="hidden" name="token" value="'.esc_attr(rawurlencode($tok)).'">
			<input type="hidden" name="scope" value="'.$single.'">
			<button type="submit" name="crit_ht_confirm_delete" class="button button-small button-secondary">🗑 Видалити</button>
		</form>';
	}

	$actions .= '</div>';

	echo '<tr>
			<td><code>'.esc_html($tok).'</code></td>
			<td style="text-align:right">'.intval($info['count']).'</td>
			<td>'.esc_html($foundIn).'</td>
			<td>'.$actions.'</td>
		</tr>';
}

	echo '</tbody></table>';

	// Підказка про права
	if (!is_writable($path)) {
		echo '<div class="notice notice-warning" style="margin-top:10px"><p>⚠️ Файл <code>'.esc_html($path).'</code> лише для читання — запис змін неможливий. Надай права на запис і онови сторінку.</p></div>';
	}
	
	echo '</div>';
}

/** Пункт меню — привʼязуємо нову версію рендера */
add_action('admin_menu', function() {
	add_submenu_page(
		'critical-event-logs',
		'Заблоковані IP (.htaccess)',
		'Заблоковані IP',
		'manage_options',
		'crit-htaccess-blocks',
		'crit_ht_blocklist_admin_page_v2'
	);
});
