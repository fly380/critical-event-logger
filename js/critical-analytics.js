/* Critical Logger — Analytics Dashboard (Chart.js v4)
 * Renders 3 charts + KPI cards. Requires:
 *	- window.critAnalyticsData = { ajaxUrl, nonce }
 *	- Chart.js loaded beforehand
 */

(function ($) {
	const $root = $('#crit-analytics-root');

	// ---------- helpers ----------
	const el = (tag, attrs = {}, html = '') => {
		const $e = $(document.createElement(tag));
		Object.entries(attrs).forEach(([k, v]) => $e.attr(k, v));
		if (html) $e.html(html);
		return $e;
	};

	const number = (n) =>
		(n || 0).toLocaleString(undefined, { maximumFractionDigits: 0 });

	const sum = (obj) => Object.values(obj || {}).reduce((a, b) => a + b, 0);

	const showError = (msg) => {
		$root.html(
			`<div class="notice notice-error" style="padding:12px"><p>${msg}</p></div>`
		);
	};

	const showLoading = () => {
		$root.html(`
			<div class="crit-anal-loading" style="display:grid;gap:12px">
				<div class="crit-skel" style="height:48px;background:#f1f1f1;border-radius:8px"></div>
				<div class="crit-skel" style="height:280px;background:#f1f1f1;border-radius:8px"></div>
				<div class="crit-skel" style="height:280px;background:#f1f1f1;border-radius:8px"></div>
				<div class="crit-skel" style="height:280px;background:#f1f1f1;border-radius:8px"></div>
			</div>
		`);
	};

	// ---------- UI skeleton ----------
	const renderShell = () => {
		const $wrap = el(
			'div',
			{ class: 'crit-anal-wrap' },
			`
			<style>
				.crit-anal-wrap{display:flex;flex-direction:column;gap:16px}
				.crit-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
				@media (max-width:1200px){.crit-kpis{grid-template-columns:repeat(2,minmax(0,1fr))}}
				@media (max-width:600px){.crit-kpis{grid-template-columns:1fr}}
				.crit-card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:14px}
				.crit-card h3{margin:0 0 6px;font-size:13px;color:#6b7280;text-transform:uppercase;letter-spacing:.04em}
				.crit-card .crit-kpi{font-size:22px;font-weight:700}
				.crit-grid{display:grid;grid-template-columns:1fr;gap:12px}
				.crit-chart{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:12px}
				.crit-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
				.crit-hdr h2{margin:0;font-size:16px}
				.crit-controls{display:flex;gap:8px;align-items:center}
				.crit-input{padding:6px 8px;border:1px solid #e5e7eb;border-radius:6px}
				.crit-btn{padding:6px 10px;border:1px solid #e5e7eb;border-radius:6px;background:#fff;cursor:pointer}
				.crit-btn[disabled]{opacity:.5;cursor:not-allowed}
			</style>
			<div class="crit-controls">
				<div>
					<input type="date" class="crit-input" id="crit-date-start">
					<input type="date" class="crit-input" id="crit-date-end">
					<button class="crit-btn" id="crit-apply">Застосувати</button>
					<button class="crit-btn" id="crit-reset">Скинути</button>
				</div>
				<div style="margin-left:auto;display:flex;gap:8px;align-items:center">
					<label style="display:flex;gap:6px;align-items:center;font-size:13px;color:#374151">
						<input type="checkbox" id="crit-autorefresh"> автооновлення (60с)
					</label>
				</div>
			</div>

			<div class="crit-kpis">
				<div class="crit-card"><h3>Подій (всього)</h3><div class="crit-kpi" id="kpi-total">—</div></div>
				<div class="crit-card"><h3>Днів у вибірці</h3><div class="crit-kpi" id="kpi-days">—</div></div>
				<div class="crit-card"><h3>Унікальних IP</h3><div class="crit-kpi" id="kpi-uniqip">—</div></div>
				<div class="crit-card"><h3>Топ-країни</h3><div class="crit-kpi" id="kpi-topcountry">—</div></div>
			</div>

			<div class="crit-grid">
				<div class="crit-chart">
					<div class="crit-hdr"><h2>Динаміка подій по днях</h2></div>
					<canvas id="chart-by-day" height="90"></canvas>
				</div>
				<div class="crit-chart">
					<div class="crit-hdr"><h2>Топ країн походження</h2></div>
					<canvas id="chart-by-country" height="90"></canvas>
				</div>
				<div class="crit-chart">
					<div class="crit-hdr"><h2>Найактивніші IP</h2></div>
					<canvas id="chart-by-ip" height="90"></canvas>
				</div>
			</div>
		`
		);
		$root.html($wrap);
	};

	// ---------- data fetch ----------
	let timer = null;

	const fetchData = (filters = {}) =>
		$.post(critAnalyticsData.ajaxUrl, {
			action: 'crit_get_analytics_data',
			nonce: critAnalyticsData.nonce,
			start: filters.start || '',
			end: filters.end || ''
		});

	// ---------- charts ----------
	let chDay = null,
		chCountry = null,
		chIP = null;

	const destroyCharts = () => {
		[chDay, chCountry, chIP].forEach((c) => {
			if (c && typeof c.destroy === 'function') c.destroy();
		});
		chDay = chCountry = chIP = null;
	};

	const renderCharts = (data) => {
		// KPI
		const total = sum(data.by_day || {});
		const days = Object.keys(data.by_day || {}).length;
		const uniqIPs = Object.keys(data.by_ip || {}).length;
		const topCountry =
			Object.entries(data.by_country || {})[0]?.[0] || '—';

		$('#kpi-total').text(number(total));
		$('#kpi-days').text(number(days));
		$('#kpi-uniqip').text(number(uniqIPs));
		$('#kpi-topcountry').text(topCountry);

		// Charts
		const ctx1 = document.getElementById('chart-by-day');
		const ctx2 = document.getElementById('chart-by-country');
		const ctx3 = document.getElementById('chart-by-ip');

		const labelsDay = Object.keys(data.by_day || {});
		const valuesDay = Object.values(data.by_day || {});

		chDay = new Chart(ctx1, {
			type: 'line',
			data: {
				labels: labelsDay,
				datasets: [
					{
						label: 'Подій за день',
						data: valuesDay,
						borderWidth: 2,
						pointRadius: 2,
						tension: 0.25
					}
				]
			},
			options: {
				responsive: true,
				plugins: { legend: { display: false } },
				scales: {
					y: { beginAtZero: true, ticks: { precision: 0 } }
				}
			}
		});

		const labelsCountry = Object.keys(data.by_country || {});
		const valuesCountry = Object.values(data.by_country || {});
		chCountry = new Chart(ctx2, {
			type: 'bar',
			data: {
				labels: labelsCountry,
				datasets: [
					{ label: 'Подій', data: valuesCountry, borderWidth: 1 }
				]
			},
			options: {
				responsive: true,
				plugins: { legend: { display: false } },
				scales: {
					y: { beginAtZero: true, ticks: { precision: 0 } }
				}
			}
		});

		const entriesIP = Object.entries(data.by_ip || {});
		const labelsIP = entriesIP.map(([ip]) => ip);
		const valuesIP = entriesIP.map(([, v]) => v);
		chIP = new Chart(ctx3, {
			type: 'bar',
			data: {
				labels: labelsIP,
				datasets: [
					{ label: 'Подій', data: valuesIP, borderWidth: 1 }
				]
			},
			options: {
				indexAxis: 'y',
				responsive: true,
				plugins: { legend: { display: false } },
				scales: {
					x: { beginAtZero: true, ticks: { precision: 0 } }
				}
			}
		});
	};

	// ---------- filters + autorefresh ----------
	const getFilters = () => {
		const start = $('#crit-date-start').val();
		const end = $('#crit-date-end').val();
		return { start, end };
	};

	const applyFilters = async () => {
		$('#crit-apply').prop('disabled', true);
		try {
			const resp = await fetchData(getFilters());
			if (!resp || !resp.success) {
				showError('Помилка отримання даних.');
				return;
			}
			destroyCharts();
			renderCharts(resp.data || {});
		} finally {
			$('#crit-apply').prop('disabled', false);
		}
	};

	const resetFilters = () => {
		$('#crit-date-start').val('');
		$('#crit-date-end').val('');
		applyFilters();
	};

	const toggleAutorefresh = (on) => {
		if (timer) {
			clearInterval(timer);
			timer = null;
		}
		if (on) {
			timer = setInterval(applyFilters, 60000);
		}
	};

	// ---------- init ----------
	(async function init() {
		showLoading();
		renderShell();

		// defaults: last 14 days (only set inputs; server can still send all)
		const now = new Date();
		const toISO = (d) => d.toISOString().slice(0, 10);
		const start = new Date(now);
		start.setDate(now.getDate() - 13);
		$('#crit-date-start').val(toISO(start));
		$('#crit-date-end').val(toISO(now));

		// events
		$('#crit-apply').on('click', applyFilters);
		$('#crit-reset').on('click', resetFilters);
		$('#crit-autorefresh').on('change', function () {
			toggleAutorefresh(this.checked);
		});

		// first load
		await applyFilters();
	})();
})(jQuery);
