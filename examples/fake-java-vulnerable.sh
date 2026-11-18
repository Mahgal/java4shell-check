#!/bin/sh
# Fixture java binary (NOT a real JVM): prints a real-format `java -version`
# for an AFFECTED build, to stderr, and exits 0.
# Use it to try --java-path on a machine without Java installed:
#   python3 java4shell_check.py --java-path examples/fake-java-vulnerable.sh
echo 'openjdk version "17.0.21" 2025-10-21' >&2
echo 'OpenJDK Runtime Environment (build 17.0.21+9)' >&2
echo 'OpenJDK 64-Bit Server VM (build 17.0.21+9, mixed mode, sharing)' >&2
