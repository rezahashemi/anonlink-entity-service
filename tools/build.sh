#!/usr/bin/env bash
cd backend
docker build -t quay.io/n1analytics/entity-app .
cd ../frontend
docker build -t quay.io/n1analytics/entity-nginx .
cd ..
