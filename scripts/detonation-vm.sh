#!/bin/bash
# Boot script for the disposable detonation VM. scripts/detonation-vm.ps1 fills in the four
# placeholders and passes it as the VM's custom data, and cloud-init runs it once, as root.
# It installs Docker, marks the VM as disposable, and registers a GitHub Actions runner that
# takes one job and then unregisters. See docs/development.md#detonation-vm.
set -euo pipefail

RUNNER_VERSION=2.338.2
RUNNER_SHA256=baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40
REPO_URL="__REPO_URL__"
RUNNER_NAME="__RUNNER_NAME__"
TOKEN="__TOKEN__"
MAX_MINUTES="__MAX_MINUTES__"

# A backstop if the script that made this VM stops: power off after the time limit. Azure
# still bills a VM that is powered off from inside until it is deallocated or deleted.
shutdown -h "+$MAX_MINUTES"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends docker.io git gh curl ca-certificates
systemctl enable --now docker

# What the benchmark workflow checks before it detonates anything.
mkdir -p /etc/bombsquad
touch /etc/bombsquad/disposable-vm

useradd --create-home --shell /bin/bash runner
usermod -aG docker runner
cd /home/runner
curl -fsSL -o runner.tar.gz \
  "https://github.com/actions/runner/releases/download/v$RUNNER_VERSION/actions-runner-linux-x64-$RUNNER_VERSION.tar.gz"
echo "$RUNNER_SHA256  runner.tar.gz" | sha256sum -c -
tar -xzf runner.tar.gz
rm runner.tar.gz
./bin/installdependencies.sh
chown -R runner:runner /home/runner

# The default labels self-hosted, Linux and X64 are kept; the workflow asks for all four.
# The runner may update itself from GitHub's releases if GitHub no longer accepts this one.
sudo -u runner ./config.sh --unattended --ephemeral --url "$REPO_URL" \
  --token "$TOKEN" --name "$RUNNER_NAME" --labels bombsquad-detonation
# The registration token is no longer needed. Remove the copies of this script that the VM
# keeps, as far as they are known; the token expires an hour after it was made anyway.
TOKEN=""
rm -f /var/lib/cloud/instance/user-data.txt /var/lib/cloud/instance/user-data.txt.i \
  /var/lib/cloud/instance/scripts/part-* /var/lib/waagent/CustomData
sed -i 's|<ns1:CustomData>[^<]*</ns1:CustomData>||' /var/lib/waagent/ovf-env.xml 2>/dev/null || true

# Its own service, so the runner outlives cloud-init. It exits after its one job.
systemd-run --unit bombsquad-runner --uid runner --gid runner \
  --property WorkingDirectory=/home/runner /home/runner/run.sh
