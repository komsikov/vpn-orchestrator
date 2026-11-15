#!/usr/bin/env bash
set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if [[ $EUID != 0 ]]; then
    printf '%s\n' 'Запустите установку от root.' >&2
    exit 1
fi
if ! /usr/bin/python3 -Ic 'import sys; sys.exit(sys.version_info < (3, 11))'; then
    printf '%s\n' 'Требуется Python 3.11 или новее в /usr/bin/python3.' >&2
    exit 1
fi

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
install_dir=/usr/local/libexec/vpn-orchestrator/admin
config_dir=/etc/vpn-orchestrator-admin
service_user=vpn-admin

if ! getent group "$service_user" >/dev/null; then
    groupadd --system "$service_user"
fi
if ! getent passwd "$service_user" >/dev/null; then
    login_shell=$(command -v nologin)
    useradd --system --gid "$service_user" --no-create-home --home-dir /nonexistent \
        --shell "$login_shell" "$service_user"
fi
if [[ $(id -gn "$service_user") != "$service_user" || $(id -u "$service_user") == 0 ]]; then
    printf '%s\n' 'Для панели нужна отдельная служебная учётная запись vpn-admin с группой vpn-admin.' >&2
    exit 1
fi

install -d -o root -g root -m 0755 "$install_dir" "$install_dir/static"
install -d -o root -g "$service_user" -m 0750 "$config_dir"
install -o root -g root -m 0644 \
    "$source_dir/web.py" "$source_dir/settings.py" "$source_dir/set_password.py" "$install_dir/"
install -o root -g root -m 0600 "$source_dir/helper.py" "$install_dir/helper.py"
install -o root -g root -m 0644 \
    "$source_dir/static/index.html" "$source_dir/static/style.css" "$source_dir/static/app.js" "$install_dir/static/"
install -o root -g root -m 0644 \
    "$source_dir/systemd/vpn-admin.service" "$source_dir/systemd/vpn-admin-worker.socket" \
    "$source_dir/systemd/vpn-admin-worker@.service" /etc/systemd/system/

config_file=$config_dir/config.toml
if [[ ! -e "$config_file" && ! -L "$config_file" ]]; then
    install -o root -g "$service_user" -m 0640 "$source_dir/config.example.toml" "$config_file"
fi
printf 'Файлы панели установлены. Настройте %s и задайте пароль перед запуском.\n' "$config_file"
