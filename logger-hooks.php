<?php
/**
 * Critical Event Logger — helper module
 * Copyright © 2025 Казмірчук Андрій
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */
// Захист від прямого доступу
if (!defined('ABSPATH')) {
	exit;
}

require_once plugin_dir_path(__FILE__) . 'critical-logger.php'; // припускаємо, що log-функція тут

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
		critical_logger_log("ВИДАЛЕНО ЗАПИС ({$post->post_type}): {$post->post_title} [ID: $post_id]");
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

// Запускаємо хук-реєстрацію
add_action('init', 'critical_logger_init_hooks');