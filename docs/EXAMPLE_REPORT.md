# Discord API Security Research Lab report

## Summary

- Endpoints: 4
- Scenarios: 3
- Findings: 18

## By module

| Module | Count |
| --- | --- |
| rest | 4 |
| oauth | 6 |
| gateway | 5 |
| permissions | 3 |
| lab | 0 |

## By severity

| Severity | Count |
| --- | --- |
| critical | 1 |
| high | 6 |
| low | 6 |
| medium | 5 |

## Findings

| Module | ID | Title | Severity | Evidence | Recommendation |
| --- | --- | --- | --- | --- | --- |
| permissions | perm-admin-granted | Роли выдано право ADMINISTRATOR | critical | bot | Уберите ADMINISTRATOR и выдайте только конкретные права. |
| oauth | oauth-dangerous-scope | Запрошены опасные OAuth2-права | high | guilds.join | Уберите права, которые приложению не нужны, и согласуйте их с пользователем. |
| oauth | oauth-redirect-insecure | Небезопасный redirect URI | high | http://example.test/callback | Используйте точный HTTPS URI или localhost для локальной разработки. |
| oauth | oauth-redirect-insecure | Небезопасный redirect URI | high | https://example.test/* | Используйте точный HTTPS URI или localhost для локальной разработки. |
| oauth | oauth-token-auth-none | Token endpoint не аутентифицирует клиента | high | token_endpoint_auth_method=none | Используйте client_secret_basic или client_secret_post. |
| permissions | perm-excessive | У роли избыточные права | high | moderator-global: BAN_MEMBERS | Оставьте только права, необходимые роли для работы. |
| rest | rest-auth-missing | Endpoint доступен без авторизации | high | GET /api/v10/private/data | Включите проверку авторизации или явно объявите endpoint публичным. |
| gateway | gateway-heartbeat-range | Интервал heartbeat вне допустимого диапазона | medium | heartbeat_interval=500 | Используйте интервал из HELLO и отправляйте heartbeat вовремя. |
| oauth | oauth-pkce-disabled | PKCE отключён | medium | pkce=false | Включите PKCE для публичных OAuth2-клиентов. |
| oauth | oauth-state-disabled | Защита state отключена | medium | state=false | Включайте непредсказуемый state и проверяйте его в callback. |
| permissions | perm-global-scope | Опасные права выданы в глобальном контексте | medium | moderator-global | Ограничьте эти права конкретным сервером или приложением. |
| rest | rest-rate-limit-missing | У endpoint не описано ограничение частоты запросов | medium | POST /api/v10/channels/100000000000000003/messages | Опишите rate limit и проверяйте заголовки X-RateLimit-* и Retry-After. |
| gateway | gateway-intents-empty | Не объявлены intents | low | intents=[] | Запросите только те intents, которые действительно нужны. |
| gateway | gateway-old-version | Используется устаревшая версия Gateway | low | version=9 | Обновитесь до актуальной версии протокола Gateway. |
| gateway | gateway-ready-missing | В списке событий нет READY | low | events без READY | Добавьте обработку READY как начала успешного соединения. |
| gateway | gateway-resume-disabled | Возобновление сессии отключено | low | resume=false | Поддерживайте RESUME, чтобы не терять события после разрыва. |
| rest | rest-401-not-documented | Для защищённого endpoint не описан ответ 401 | low | POST /api/v10/channels/100000000000000003/messages | Добавьте код 401 в документацию ответов endpoint. |
| rest | rest-errors-not-documented | Для POST-запроса не описаны коды ошибок | low | POST /api/v10/channels/100000000000000003/messages | Перечислите возможные коды ошибок в документации endpoint. |

## Permission bits

| Role | Bits | Names | Excessive |
| --- | --- | --- | --- |
| reader | 1024 | VIEW_CHANNEL | no |
| bot | 8 | ADMINISTRATOR | yes |
| moderator-global | 4 | BAN_MEMBERS | yes |

## Scenario results

| ID | Status | Severity | Notes |
| --- | --- | --- | --- |
| ratelimit-001 | reproduced | medium | Локальная симуляция на mock-сервере: Ответ 429 без корректной обработки Retry-After (/api/v10/rate-limited) |
| forbidden-002 | fixed | low | Проверка исправления: проверка прав доступа перед запросом |
| auth-003 | reproduced | high | Локальная симуляция на mock-сервере: Синтетический профиль после авторизации (/api/v10/users/@me) |

## Recommendations

1. Уберите ADMINISTRATOR и выдайте только конкретные права.
2. Уберите права, которые приложению не нужны, и согласуйте их с пользователем.
3. Используйте точный HTTPS URI или localhost для локальной разработки.
4. Используйте client_secret_basic или client_secret_post.
5. Оставьте только права, необходимые роли для работы.
6. Включите проверку авторизации или явно объявите endpoint публичным.
7. Используйте интервал из HELLO и отправляйте heartbeat вовремя.
8. Включите PKCE для публичных OAuth2-клиентов.
9. Включайте непредсказуемый state и проверяйте его в callback.
10. Ограничьте эти права конкретным сервером или приложением.
11. Опишите rate limit и проверяйте заголовки X-RateLimit-* и Retry-After.
12. Запросите только те intents, которые действительно нужны.
13. Обновитесь до актуальной версии протокола Gateway.
14. Добавьте обработку READY как начала успешного соединения.
15. Поддерживайте RESUME, чтобы не терять события после разрыва.
16. Добавьте код 401 в документацию ответов endpoint.
17. Перечислите возможные коды ошибок в документации endpoint.

Note: all data is synthetic and all secrets are masked.
