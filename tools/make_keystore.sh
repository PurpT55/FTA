#!/usr/bin/env bash
# Creates android/suite.keystore used to sign BOTH apps with the same key.
# Change the passwords for anything beyond personal use (and export SUITE_* env vars).
set -euo pipefail
cd "$(dirname "$0")/../android"
if [ -f suite.keystore ]; then echo "suite.keystore already exists"; exit 0; fi
keytool -genkeypair -v -keystore suite.keystore -storepass droidsuite -keypass droidsuite \
  -alias suite -keyalg RSA -keysize 3072 -validity 10000 \
  -dname "CN=DroidSuite local build, O=Personal, C=XX"
echo "Created android/suite.keystore"
