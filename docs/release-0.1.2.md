Исправление подключения INCY для Windows.

- Профиль маршрутизации больше не ссылается на `geosite:ru-inside`: российские
  домены передаются явным списком. INCY для Windows использовал встроенный
  geosite.dat без этой категории, и подключение завершалось ошибкой
  «failed to check code RU-INSIDE from geosite.dat».
- Ревизия geo-данных определяется через git, без лимита GitHub API.
- Включает исправления 0.1.1: установка на Ubuntu без отката после запуска
  служб, журнал на Ubuntu, вывод причины ошибки, проверка совместимости
  Reality target.

Установка на чистом Ubuntu VPS:

```bash
curl -fsSL https://github.com/RLTEX/RUAVC-next/releases/latest/download/ruavc-setup.sh | sudo bash
sudo ruavc add phone
sudo ruavc qr phone
```

Поддерживаемые системы: Ubuntu 22.04, 24.04, 26.04; amd64 и arm64.
Настройки применяются с проверкой, backup и rollback. Доступны устройства,
Reality, direct, sites, диагностика и отдельные обновления компонентов.

Перед установкой требуется разрешить входящие TCP-порты, указанные установщиком,
в firewall ОС/хостинга. По умолчанию: 80, 443 и 9443. Старые установки RUAVC
автоматически не заменяются. Внешняя доступность из РФ не проверяется локальным
self-test. Полный перечень ограничений находится в docs/security.md.

Assets: ruavc-setup.sh, ruavc.pyz, SHA256SUMS. Bootstrap содержит контрольную сумму
конкретной версии ruavc.pyz. Сборка релиза выполняется после обязательных тестов.
