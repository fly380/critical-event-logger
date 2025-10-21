<?php
/**
 * Critical Event Logger — helper module
 * Copyright © 2025 Казмірчук Андрій
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */
if (!defined('ABSPATH')) {
	exit;
}

require_once plugin_dir_path(__FILE__) . 'critical-logger.php'; // лог-функція

function critical_logger_init_hooks() {

	// Успішний вхід
	add_action('wp_login', function($user_login, $user) {
		critical_logger_log("УСПІШНИЙ ВХІД: $user_login ({$user->user_email})");
	}, 10, 2);

	// Невдалий вхід
	add_action('wp_login_failed', function($username) {
		critical_logger_log("ПОМИЛКА ВХОДУ: $username");
	});

	// Вихід користувача
	add_action('wp_logout', function() {
		$user = wp_get_current_user();
		$username = $user->user_login ?? 'невідомо';
		critical_logger_log("ВИХІД КОРИСТУВАЧА: $username");
	});

	// Реєстрація нового користувача
	add_action('user_register', function($user_id) {
		$user = get_userdata($user_id);
		critical_logger_log("НОВИЙ КОРИСТУВАЧ: {$user->user_login} ({$user->user_email})");
	});

	// Видалення користувача
	add_action('delete_user', function($user_id) {
		$user = get_userdata($user_id);
		critical_logger_log("ВИДАЛЕНО КОРИСТУВАЧА: {$user->user_login} ({$user->user_email})");
	});

	// Зміна пароля
	add_action('after_password_reset', function($user, $new_pass) {
		critical_logger_log("ЗМІНА ПАРОЛЯ: {$user->user_login}");
	}, 10, 2);

	// Оновлення профілю
	add_action('profile_update', function($user_id, $old_user_data) {
		$user = get_userdata($user_id);
		critical_logger_log("ОНОВЛЕНО ПРОФІЛЬ: {$user->user_login}");
	}, 10, 2);

	// Збереження запису (створення / оновлення)
	add_action('save_post', function($post_id, $post, $update) {
		if ($post->post_type === 'revision') return;
		$action = $update ? 'ОНОВЛЕНО' : 'СТВОРЕНО';
		critical_logger_log("$action ЗАПИС ({$post->post_type}): {$post->post_title} [ID: $post_id]");
	}, 10, 3);

	// Видалення запису
	add_action('before_delete_post', function($post_id) {
		$post = get_post($post_id);
		if ($post) {
			critical_logger_log("ВИДАЛЕНО ЗАПИС ({$post->post_type}): {$post->post_title} [ID: $post_id]");
		}
	});

	// Активація плагіну
	add_action('activated_plugin', function($plugin) {
		critical_logger_log("АКТИВОВАНО ПЛАГІН: $plugin");
	});

	// Деактивація плагіну
	add_action('deactivated_plugin', function($plugin) {
		critical_logger_log("ДЕАКТИВОВАНО ПЛАГІН: $plugin");
	});

	// Зміна теми
	add_action('switch_theme', function($new_name, $new_theme) {
		critical_logger_log("ЗМІНА ТЕМИ: $new_name");
	}, 10, 2);
}
add_action('init', 'critical_logger_init_hooks');


/* === Додаткові корисні події === */
if ( ! function_exists('critical_logger_more_hooks') ) {
	function critical_logger_more_hooks() {

		/* Користувачі/ролі */
		add_action('set_user_role', function($user_id, $role, $old_roles){
			$user = get_userdata($user_id);
			$old  = is_array($old_roles) ? implode(',', $old_roles) : (string)$old_roles;
			if ($user) critical_logger_log("ЗМІНА РОЛІ: {$user->user_login} {$old} → {$role}", 'INFO');
		}, 10, 3);

		if ( is_multisite() ) {
			add_action('grant_super_admin',  function($user_id){ $u = get_userdata($user_id); if ($u) critical_logger_log("GRANT SUPER ADMIN: {$u->user_login}", 'WARNING'); });
			add_action('revoke_super_admin', function($user_id){ $u = get_userdata($user_id); if ($u) critical_logger_log("REVOKE SUPER ADMIN: {$u->user_login}", 'WARNING'); });
		}

		add_action('retrieve_password_key', function($user_login, $key){
			critical_logger_log("RESET PASSWORD REQUEST: {$user_login}", 'NOTICE');
		}, 10, 2);

		/* Коментарі */
		add_action('comment_post', function($comment_ID, $approved, $data){
			critical_logger_log("КОМЕНТАР СТВОРЕНО: ID {$comment_ID}, статус=" . (is_numeric($approved)? (int)$approved : $approved));
		}, 10, 3);

		add_action('wp_set_comment_status', function($comment_ID, $status){
			critical_logger_log("КОМЕНТАР СТАТУС: ID {$comment_ID} → {$status}");
		}, 10, 2);

		foreach (['trashed_comment','spammed_comment','unspammed_comment','deleted_comment'] as $h) {
			add_action($h, function($comment_ID) use ($h){
				critical_logger_log(strtoupper($h) . ": ID {$comment_ID}", ($h === 'spammed_comment') ? 'WARNING' : 'INFO');
			});
		}

		/* Медіа */
		add_action('add_attachment', function($post_id){
			$p = get_post($post_id);
			if ($p) critical_logger_log("МЕДІА ДОДАНО: {$p->post_title} [ID: {$post_id}]");
		});
		add_action('delete_attachment', function($post_id){
			critical_logger_log("МЕДІА ВИДАЛЕНО: ID {$post_id}", 'WARNING');
		});

		/* Меню / кастомайзер */
		add_action('wp_update_nav_menu', function($menu_id, $data){
			$name = wp_get_nav_menu_object($menu_id);
			critical_logger_log("МЕНЮ ОНОВЛЕНО: " . ($name ? $name->name : $menu_id));
		}, 10, 2);

		add_action('customize_save_after', function($wp_customize){
			critical_logger_log("CUSTOMIZER SAVE (налаштування теми)");
		});

		/* Оновлення ядра/тем/плагінів */
		add_action('upgrader_process_complete', function($upgrader, $hook_extra){
			$type  = isset($hook_extra['type']) ? $hook_extra['type'] : 'unknown';
			$action= isset($hook_extra['action']) ? $hook_extra['action'] : 'unknown';
			$items = [];
			if (!empty($hook_extra['plugins'])) $items = (array)$hook_extra['plugins'];
			if (!empty($hook_extra['themes']))  $items = (array)$hook_extra['themes'];
			if (!empty($hook_extra['core']))    $items = ['core'];
			critical_logger_log("UPGRADER: {$type} {$action} → " . implode(', ', $items), ($action === 'update' ? 'NOTICE' : 'INFO'));
		}, 10, 2);

		add_action('automatic_updates_complete', function($results){
			critical_logger_log("AUTOMATIC UPDATES COMPLETE", 'NOTICE');
		});

		/* Зміна опцій (маскуємо секрети) */
add_action('updated_option', function($option, $old, $new){
	$name = (string)$option;

	// --- ІГНОРУЄМО шумні системні опції ---
	$ignored_exact = [
		'cron',
		'cron_timestamps',
		'external_updates-critical-event-logger', // ← додали конкретну
	];
	$ignored_prefixes = [
		'_transient_', '_site_transient_', '_transient_timeout_',
		'theme_mods_', 'auto_plugin_theme_', 'can_compress_scripts',
		'external_updates-', // ← і загальний префікс для подібних
	];

	$skip = in_array($name, $ignored_exact, true);
	if (!$skip) {
		foreach ($ignored_prefixes as $p) {
			if (strpos($name, $p) === 0) { $skip = true; break; }
		}
	}

	// Дозволяємо перевизначити ззовні
	$skip = (bool) apply_filters('critical_logger_skip_updated_option', $skip, $name, $old, $new);
	if ($skip) return;
	// --------------------------------------

	$mask = (bool)preg_match('/(pass|secret|key|token|salt)/i', $name);
	$oldS = $mask ? '[masked]' : (is_scalar($old) ? (string)$old : '[complex]');
	$newS = $mask ? '[masked]' : (is_scalar($new) ? (string)$new : '[complex]');

	critical_logger_log("UPDATED OPTION: {$name} ({$oldS} → {$newS})", $mask ? 'NOTICE' : 'INFO');
}, 10, 3);

		/* REST API: лог лише 4xx/5xx */
		add_filter('rest_post_dispatch', function($response, $server, $request){
			try {
				$status = (is_object($response) && method_exists($response, 'get_status')) ? $response->get_status() : 200;
				if ($status >= 400) {
					$route  = method_exists($request, 'get_route')  ? $request->get_route()  : '';
					$method = method_exists($request, 'get_method') ? $request->get_method() : '';
					$user   = function_exists('wp_get_current_user') ? wp_get_current_user() : null;
					$u      = ($user && $user->exists()) ? $user->user_login : 'guest';
					$ip     = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '-';
					critical_logger_log("REST {$status} {$method} {$route} (user={$u}, ip={$ip})", ($status >= 500 ? 'ERROR' : 'WARNING'));
				}
			} catch (\Throwable $e) {
				// ігноруємо помилки під час логування
			}
			return $response;
		}, 10, 3);

		/* 404 */
		add_action('template_redirect', function(){
			if (function_exists('is_404') && is_404()) {
				$uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
				critical_logger_log("404: {$uri}", 'WARN');
			}
		});

		/* Пошта */
		add_action('wp_mail_failed', function($wp_error){
			if (is_wp_error($wp_error)) {
				critical_logger_log("WP_MAIL_FAILED: " . $wp_error->get_error_message(), 'ERROR');
			}
		});

		/* XML-RPC */
		add_action('xmlrpc_call', function($method){
			critical_logger_log("XML-RPC CALL: {$method}", 'NOTICE');
		});
		add_filter('xmlrpc_login_error', function($error){
			if (is_wp_error($error)) {
				critical_logger_log("XML-RPC LOGIN ERROR: " . $error->get_error_message(), 'ERROR');
			}
			return $error;
		});

		/* Редактор файлів у /wp-admin/ (через AJAX) */
		add_action('wp_ajax_edit-theme-plugin-file', function(){
			$user = wp_get_current_user();
			if ($user) critical_logger_log("ADMIN FILE EDIT via AJAX: {$user->user_login}", 'WARNING');
		});

		/* Інтеграції з популярними плагінами */
		// WooCommerce
		if ( class_exists('WooCommerce') ) {
			add_action('woocommerce_order_status_changed', function($order_id, $from, $to){
				critical_logger_log("WC ORDER {$order_id}: {$from} → {$to}", 'NOTICE');
			}, 10, 3);
			add_action('woocommerce_low_stock', function($product){
				$p = (is_object($product) && method_exists($product, 'get_name')) ? $product->get_name() : 'product';
				critical_logger_log("WC LOW STOCK: {$p}", 'WARNING');
			});
		}
		// Contact Form 7
		if ( function_exists('wpcf7') ) {
			add_action('wpcf7_mail_failed', function($cf7){
				$id = (is_object($cf7) && method_exists($cf7, 'id')) ? $cf7->id() : '-';
				critical_logger_log("CF7 MAIL FAILED: {$id}", 'ERROR');
			});
			add_action('wpcf7_mail_sent', function($cf7){
				$id = (is_object($cf7) && method_exists($cf7, 'id')) ? $cf7->id() : '-';
				critical_logger_log("CF7 MAIL SENT: {$id}", 'INFO');
			});
		}
	}
	add_action('init', 'critical_logger_more_hooks');
}
