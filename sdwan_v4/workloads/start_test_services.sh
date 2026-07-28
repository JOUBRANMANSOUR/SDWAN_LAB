#!/bin/sh
set -eu
size_mb="${1:-200}"
case "$size_mb" in *[!0-9]*|'') echo 'size must be a positive integer' >&2; exit 2;; esac
mkdir -p /srv/www /srv/ftp /run/sshd
truncate -s "${size_mb}M" /srv/www/sdwan-${size_mb}M.bin
cp /srv/www/sdwan-${size_mb}M.bin /srv/ftp/
nginx -t
nginx
cat >/run/vsftpd-sdwan.conf <<'EOF'
listen=YES
listen_ipv6=NO
anonymous_enable=YES
no_anon_password=YES
anon_root=/srv/ftp
write_enable=NO
pasv_enable=YES
pasv_min_port=30000
pasv_max_port=30010
seccomp_sandbox=NO
EOF
vsftpd /run/vsftpd-sdwan.conf &
ssh-keygen -A
/usr/sbin/sshd
server_ip="$(hostname -I | awk '{print $1}')"
dnsmasq --no-daemon --port=53 --listen-address="$server_ip" \
  --bind-interfaces --address="/sdwan-lab.local/$server_ip" >/tmp/dnsmasq.log 2>&1 &
python3 /opt/sdwan_v4/workloads/quic_test.py server --bind "$server_ip" \
  >/tmp/quic-server.log 2>&1 &
echo "HTTP/HTTPS, QUIC, DNS, anonymous FTP, and SSH services started; file=sdwan-${size_mb}M.bin"


