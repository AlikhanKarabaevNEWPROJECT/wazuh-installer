# wazuh-installer / Автоматический инсталлятор Wazuh

## О проекте / About

Этот bash-скрипт полностью автоматизирует установку и настройку Wazuh стека (Indexer, Manager, Filebeat и Dashboard) на Debian.  
Скрипт создаёт и настраивает сертификаты, конфиги, systemd-сервисы и обеспечивает безопасность компонентов.

This bash script fully automates the installation and configuration of the Wazuh stack (Indexer, Manager, Filebeat, and Dashboard) on Debian.  
The script generates and configures certificates, config files, systemd services, and ensures component security.

---

## Особенности / Features

- Полная автоматизация установки Wazuh 4.12.0  
- Создание и настройка SSL сертификатов для безопасности  
- Конфигурация всех основных компонентов Wazuh  
- Настройка Filebeat с шаблонами и безопасным хранением секретов  
- Активация и запуск всех сервисов systemd  
- Оптимизирован для Debian-based систем

- Full automation of Wazuh 4.12.0 installation  
- SSL certificate generation and configuration for security  
- Configuration of all main Wazuh components  
- Filebeat setup with templates and secure secret storage  
- Systemd service activation and start  
- Optimized for Debian-based systems

---

## Как использовать / How to use

1. Клонируйте репозиторий / Clone the repo:  
   `git clone https://github.com/AlikhanKarabaevNEWPROJECT/wazuh-installer.git`

2. Перейдите в папку / Change directory:  
   `cd wazuh-installer`

3. Запустите скрипт от root:  
   `sudo bash install.sh`

---

## Автор / Author

Alikhan Karabaev (AlikhanKarabaevNEWPROJECT)  
https://github.com/AlikhanKarabaevNEWPROJECT

---

## Лицензия / License

MIT License  
Свободно использовать и модифицировать.

---

Спасибо за использование и поддержку! / Thanks for using and supporting!
