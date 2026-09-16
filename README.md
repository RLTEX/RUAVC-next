# RUAVC 0.1.2

Личный VLESS Reality VPN на Ubuntu VPS с подписками для INCY.
Простой по умолчанию, гибкий при необходимости.

Требуются Ubuntu **22.04, 24.04 или 26.04**, архитектура **amd64 или arm64**,
публичный IPv4, systemd и доступ root. Для первой установки используется чистый VPS.

## Начало работы

На сервере:

```bash
curl -fsSL https://github.com/RLTEX/RUAVC-next/releases/latest/download/ruavc-setup.sh | sudo bash
sudo ruavc add phone
sudo ruavc qr phone
```

В INCY: **«Добавить / Add» → «Подписка / Subscription»** → ссылка или QR-код.
Отдельное устройство получает собственные UUID и ссылку.

Установщик определяет IPv4 и страну, проверяет несколько независимых кандидатов
Reality и выбирает доступный с TLS 1.3, HTTP/2 и корректным сертификатом.
По умолчанию российские ресурсы и локальные сети открываются напрямую.
Другой трафик идёт через VPN.

Обычно используются TCP **443** для VPN и **9443** для HTTPS подписок.
Если 443 занят, выбирается свободный альтернативный порт. TCP **80** нужен
для получения и продления сертификата. Итоговые порты выводятся установщиком.
Firewall ОС и хостинга остаётся под управлением администратора; эти входящие
порты должны быть разрешены. Чужие службы и конфигурация nginx не заменяются.

Без собственного домена применяется адрес `<IPv4-с-дефисами>.sslip.io`.
Возможны ограничения общего DNS-домена или Let's Encrypt; доступен собственный домен:

```bash
curl -fsSL https://github.com/RLTEX/RUAVC-next/releases/latest/download/ruavc-setup.sh \
  | sudo bash -s -- --domain vpn.example.com
```

Для `vpn.example.com` требуется A-запись на IPv4 VPS. Повторная установка
проверяет существующее состояние и сохраняет настройки. Обновление выполняется
отдельной командой, а прежняя реализация RUAVC автоматически не перезаписывается.

## Ежедневные команды

```bash
sudo ruavc status
sudo ruavc add laptop
sudo ruavc qr laptop
sudo ruavc reissue laptop
sudo ruavc revoke laptop

sudo ruavc direct on
sudo ruavc direct off
sudo ruavc sites add proxy example.ru
sudo ruavc sites add direct example.org
```

`status` показывает состояние без секретов. `qr` и `link` явно раскрывают ссылку,
которая даёт доступ к VPN. `reissue` меняет **и UUID, и ссылку**: старый импорт
прекращает работать, в INCY требуется новая подписка. `revoke` отключает устройство.

`direct off` убирает автоматический прямой доступ к российским ресурсам.
Локальные сети и собственные правила сохраняются. Правило `proxy` имеет приоритет
над `direct`. На устройствах изменения появляются после обновления подписки.

## Настройка и проверка

```bash
sudo ruavc config
sudo ruavc config set reality.target www.example.com:443 reality.sni www.example.com
sudo ruavc config set reality.port 2053
sudo ruavc reality check
sudo ruavc reality auto
sudo ruavc doctor
sudo ruavc logs
```

Домен в примере настройки обозначает выбранный целевой TLS-сайт; перед применением
проверяются его доступность, сертификат, TLS 1.3, HTTP/2 и размер первого ответа TLS:
REALITY не работает с target, чей ответ больше 8192 байт (например, длинная
цепочка сертификатов с OCSP). Универсального target нет.
Несколько пар параметров в `config set` применяются одной транзакцией.
Перед применением создаётся резервная точка. Ошибка проверки или запуска приводит
к автоматическому восстановлению предыдущего состояния.

`status` не обращается во внешнюю сеть. `doctor` отдельно проверяет конфигурацию,
службы, Reality, HTTPS подписок, геоданные и сеть. VLESS self-test проверяет
подключение **самого VPS**. **Внешняя доступность из РФ не проверена** — для неё
нужен клиент или независимая точка проверки в РФ.

## Обновление и восстановление

```bash
sudo ruavc check-update
sudo ruavc update
sudo ruavc update xray
sudo ruavc update routing
sudo ruavc backup create
sudo ruavc backup list
sudo ruavc rollback
sudo ruavc recover
```

Программа и Xray обновляются только явно; российские наборы данных — по расписанию.
Обновления сохраняют устройства, ключи, свои правила, `direct`, target и порты.
`rollback` возвращает предыдущую рабочую версию. `recover` завершает восстановление
после прерванной операции. Резервная копия содержит секреты и хранится с правами root.

[Все команды и параметры](docs/commands.md) · [Хранение и восстановление](docs/storage.md)
· [Ограничения и безопасность](docs/security.md) · [Изменения](CHANGELOG.md)

Код: [RLTEX/RUAVC-next](https://github.com/RLTEX/RUAVC-next). Лицензия MIT.
