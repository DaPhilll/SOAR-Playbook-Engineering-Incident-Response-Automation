#!/bin/bash
# Deploys the Shuffle SOAR platform via Docker Compose.
# Run on the orchestration host (SRV-SOC01).

set -e

# Clone the Shuffle repository
git clone https://github.com/Shuffle/Shuffle
cd Shuffle

# Initialize the frontend, backend, database, and orchestration worker containers
sudo docker-compose up -d

echo "Shuffle is starting. Check http://<SRV-SOC01-IP>:3001 once containers report healthy."
