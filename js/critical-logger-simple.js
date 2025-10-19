jQuery(document).ready(function ($) {
		/** -----------------------------
		 *	ОНОВИТИ ЛОГИ
		 * ----------------------------- */
		$('#crit-reload-logs').on('click', function () {
				const $btn = $(this);
				$btn.prop('disabled', true).text('Оновлюється...');
				$.ajax({
						url: criticalLoggerSimpleData.ajaxUrl,
						method: 'POST',
						data: {
								action: 'critical_logger_reload_logs',
								_ajax_nonce: criticalLoggerSimpleData.nonce
						},
						success: function (response) {
								if (response.success && Array.isArray(response.data)) {
										updateLogsTable(response.data);
								} else {
										alert('Помилка: ' + (response.data || 'невідомо'));
								}
						},
						error: function () {
								alert('Сталася помилка під час завантаження логів.');
						},
						complete: function () {
								$btn.prop('disabled', false).text('Оновити');
						}
				});
		});

		/** -----------------------------
		 *	ОНОВИТИ ТАБЛИЦЮ ЛОГІВ
		 * ----------------------------- */
		function updateLogsTable(lines) {
				const $tableBody = $('#crit-logs-table tbody');
				if ($tableBody.length === 0) return;

				$tableBody.empty();

				if (lines.length === 0) {
						$tableBody.append('<tr><td colspan="5">Немає записів у логах.</td></tr>');
						return;
				}

				lines.forEach(line => {
						const match = line.match(/^\[([0-9\- :]+)\]\[([^\]]+)\]\[([^\]]*)\]\[([^\]]+)\]\s?(.*)$/);
						let time = '', ip = '', username = '', level = '', message = '';
						if (match) {
								time = match[1];
								ip = match[2];
								username = match[3];
								level = match[4];
								message = match[5];
						}

						let cssClass = '';
						if (/error/i.test(level)) cssClass = 'crit-ip-danger';
						else if (/warning/i.test(level)) cssClass = 'crit-ip-warning';
						else cssClass = 'crit-ip-safe';

						const html = `
								<tr class="${cssClass}">
										<td>${time}</td>
										<td>${ip}</td>
										<td>${username}</td>
										<td>${level}</td>
										<td>${message}</td>
								</tr>
						`;
						$tableBody.append(html);
				});
		}

		/** -----------------------------
		 *	ДОДАЄМО СТИЛІ (один раз)
		 * ----------------------------- */
		if (!$('#crit-logger-styles').length) {
				const style = `
				<style id="crit-logger-styles">
						#crit-logs-table tr.crit-ip-danger td {
								background-color: #ffcccc !important;
								color: #900 !important;
						}
						#crit-logs-table tr.crit-ip-warning td {
								background-color: #fff0b3 !important;
								color: #a66a00 !important;
						}
						#crit-logs-table tr.crit-ip-safe td {
								background-color: #e9ffe9 !important;
								color: #225522 !important;
						}
						#crit-logs-table td, #crit-logs-table th {
								vertical-align: middle;
						}
						.crit-score-cell {
								font-weight: bold;
						}
				</style>`;
				$('head').append(style);
		}
});
