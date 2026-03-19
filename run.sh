#!/bin/bash

set -e

echo "[1/4] Building kernel module..."
cd kernel_module
make clean 
make

echo "[2/4] Removing old module (if loaded)..."
sudo rmmod traffic_analyzer 2>/dev/null || true

echo "[3/4] Loading kernel module..."
sudo insmod traffic_analyzer.ko

cd ..

echo "[4/4] Starting GUI..."

cd gui/build
./traffic_gui