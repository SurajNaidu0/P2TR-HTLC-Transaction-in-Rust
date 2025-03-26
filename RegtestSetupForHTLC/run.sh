#!/bin/bash

# Exit on error and execute cleanup on exit
set -e

# Function to shut down Docker on error
cleanup() {
    echo "Error detected! Shutting down Docker..."
    docker compose down
}
trap cleanup ERR

echo "Starting Docker containers..."
docker compose up -d

echo "Running Cargo application..."
cargo run

echo "Shutting down Docker containers..."
docker compose down
