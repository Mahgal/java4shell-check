#!/bin/sh
# Fixture java binary (NOT a real JVM): prints a real-format `java -version`
# for a FIXED build, to stderr, and exits 0.
#   python3 java4shell_check.py --java-path examples/fake-java-patched.sh
echo 'openjdk version "21.0.13.1" 2026-11-17' >&2
echo 'OpenJDK Runtime Environment (build 21.0.13.1+1)' >&2
echo 'OpenJDK 64-Bit Server VM (build 21.0.13.1+1, mixed mode, sharing)' >&2
