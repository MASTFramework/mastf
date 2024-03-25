#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if [[ -f "${SCRIPT_DIR}/config.sh" ]]; then
    source "${SCRIPT_DIR}/config.sh"
fi

# apply defaults
if [[ -z "${install_dir}" ]]; then
    install_dir="${SCRIPT_DIR}/.."
fi

if [[ -z "${venv_dir}" ]]; then
    venv_dir="${install_dir}/venv"
fi

if [[ -z "${python_cmd}" ]]; then
    python_cmd="python3"
fi

delimiter="----------------------------------------------------------------"

printf "\n%s\n" "${delimiter}"
printf "\e[1m\e[32mInstall script for local MAST Framework deployment\e[0m\n"
printf "%s\n" "${delimiter}"
printf "[+] \e[1m\e[34mTested on Arch Linux.\e[0m\n"

if [[ $(id -u) -eq 0 ]]; then
    printf "\n%s\n" "${delimiter}"
    printf "\e[1m\e[31mPlease do not run this script as root.\e[0m\n"
    printf "\n%s\n" "${delimiter}"
    exit 1
else
    printf "[+] Running as \e[1m\e[32m%s\e[0m user\n" "$(whoami)"
fi

if ! hash "${python_cmd}" &>/dev/null
then
    printf "\e[1m\e[31mERROR: %s is not installed, aborting...\e[0m\n" "${python_cmd}"
    exit 1
fi

if ! "${python_cmd}" -c "import venv" &>/dev/null
then
    printf "\e[1m\e[31mERROR: python3-venv is not installed, aborting...\e[0m\n"
    exit 1
fi

if [[ -z "${VIRTUAL_ENV}" ]]; then
    if [[ -f "${venv_dir}"/bin/activate ]]
    then
        source "${venv_dir}"/bin/activate
    else
        printf "\e[1m\e[31mERROR: Cannot activate python venv, aborting...\e[0m\n"
        exit 1
    fi
else
    printf "[+] python venv already active or run without venv:\n   @: ${VIRTUAL_ENV}\n"
fi

cd "${install_dir}"/ || { printf "\e[1m\e[31mERROR: Can't cd to %s/, aborting...\e[0m\n" "${install_dir}"; exit 1; }
if [[ "$HTTPS" = "false" ]]; then
    printf "[+] Disable HTTPS on NGINX\n"
    cp "$install_dir/compose/local/nginx/Dockerfile.http" "$install_dir/compose/local/nginx/Dockerfile"
    docker compose build nginx
elif [[ "$HTTPS" = "true" ]]; then
    cp "$install_dir/compose/local/nginx/Dockerfile.https" "$install_dir/compose/local/nginx/Dockerfile"
    docker compose build nginx
fi

docker compose up "$@"