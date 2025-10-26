=== Critical Event Logger ===
Contributors: fly380
Requires at least: 5.8
Tested up to: 6.8
Requires PHP: 7.2
Stable tag: 2.1.2
License: GPLv2 or later

== Description ==
Короткий опис плагіна…

== Changelog ==
= 2.1.2 – 2025-10-20 =
* Додано `CHANGELOG.md` (тепер «Список змін» видно в модалці оновлення WP).
* У логах автоматично позначається виявлений бот: `… (googlebot|bingbot|…)`.
* Підсилено перевірку пошукових ботів (reverse DNS + forward-confirm), кеш `ok/bad/na`.
* Покращено tail великих логів, стабільність AJAX.
* Збільшені тайм-аути RDAP/Cymru/Geo; дрібні правки стилів.

= 2.1.1 – 2025-10-02 =
* Публічний реліз 2.x: AJAX-перегляд логів, зведення IP, блокування IP/пулу (.htaccess),
  кеші UA/пулів/гео, ротація 30 днів, info-модалка, опція санітизації PII,
  інтеграція з PUC та локальні іконки/банери.
