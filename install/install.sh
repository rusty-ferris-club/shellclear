#!/bin/sh
set -e

get_arch() {
    a=$(uname -m | tr '[:upper:]' '[:lower:]')
    case ${a} in
        "x86_64" | "amd64" )
            echo "x86_64"
        ;;
        "aarch64" | "arm64" | "arm")
            echo "aarch64"
        ;;
        *)
            echo ${NIL}
        ;;
    esac
}

get_os() {
  platform="$(uname -s | tr '[:upper:]' '[:lower:]')"

  case "${platform}" in
    linux) platform="linux" ;;
    darwin) platform="macos" ;;
  esac

  printf '%s' "${platform}"
}

owner="rusty-ferris-club"
repo="shellclear"
bin_name=$repo
downloadFolder="${HOME}/Downloads/shellclear"
os=$(get_os)
arch=$(get_arch)
executable_folder="/usr/local/bin"

echo "[1/4] Get latest shellclear version"
version=$(curl -s --fail https://api.github.com/repos/${owner}/${repo}/releases/latest | grep tag_name | cut -d '"' -f 4)

if [[ "$version" != \v* ]]; then echo "could not get latest version"; exit 1; fi

file_name="${bin_name}-${version}-${arch}-${os}.tar.xz" 
downloaded_file="${downloadFolder}/${file_name}"

asset_uri="https://github.com/${owner}/${repo}/releases/download/${version}/${file_name}"

echo "[2/4] Download ${asset_uri} to ${downloadFolder}"
rm -rf ${downloadFolder} 
mkdir -p ${downloadFolder} 
curl --fail --location --output "${downloaded_file}" "${asset_uri}"

echo "[3/4] Install ${bin_name} to the ${executable_folder}"
tar -xvf ${downloaded_file} -C ${downloadFolder} --strip=1
mv $downloadFolder/$bin_name $executable_folder
rm -rf ${downloadFolder}
chmod +x $executable_folder/$bin_name

echo "[4/4] Set environment variables"
echo "${bin_name} was installed successfully to $downloadFolder/$bin_name"

if command -v ${bin_name} --version >/dev/null; then
    echo "Run '${bin_name} --help' to get started"
else
    echo "Manually add the directory to your \$HOME/.bash_profile (or similar)"
    echo "  export PATH=${executable_folder}:\$PATH"
    echo "Run '${bin_name} --help' to get started"
fi

exit 0