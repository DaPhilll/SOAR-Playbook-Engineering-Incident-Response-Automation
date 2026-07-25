#!/bin/bash
# Deploys the Shuffle SOAR platform on the orchestration host (SRV-SOC01).
#
# Follows the official install guide at
# https://github.com/Shuffle/Shuffle/blob/main/.github/install-guide.md
# Requires Docker, git, and a minimum of 4 GB RAM.

set -e

# Clone the Shuffle repository
git clone https://github.com/Shuffle/Shuffle
cd Shuffle

# OpenSearch prerequisites. Skipping these is the most common cause of the
# database container failing to start.
mkdir -p shuffle-database
sudo chown -R 1000:1000 shuffle-database
sudo swapoff -a

# Start the frontend, backend, Orborus worker, and OpenSearch containers.
# Compose V2 syntax (docker compose) replaces the deprecated docker-compose.
sudo docker compose up -d

echo "Shuffle is starting. Open http://<SRV-SOC01-IP>:3001 once containers report healthy."
