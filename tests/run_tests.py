#!/usr/bin/env python3
"""Tests for java4shell-check. Stdlib unittest only, no network.

Run:  python3 -m unittest discover -s tests -v
       (or: python3 tests/run_tests.py)
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import java4shell_check as j4s

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT = os.path.join(ROOT, "java4shell_check.py")

CPU_WITH = ("flags : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge "
            "avx512f avx512dq avx512cd avx512bw avx512vl avx512vbmi bmi2\n")
CPU_WITHOUT = ("flags : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge "
               "avx512f avx512dq avx512cd avx512bw avx512vl bmi2\n")


def version_stderr(version, vendor="openjdk"):
    return ('%s version "%s" 2025-10-21\n'
            "OpenJDK Runtime Environment (build %s+9)\n"
            "OpenJDK 64-Bit Server VM (build %s+9, mixed mode, sharing)\n"
            % (vendor, version, version, version))


def verdict_for(version_str, cpuinfo_text, extra_stderr=""):
    """Full pipeline verdict for a `java -version` string + cpuinfo text."""
    parsed = j4s.parse_java_version(version_stderr(version_str) + extra_stderr)
    cpu_vbmi, _detail = j4s.parse_cpuinfo(cpuinfo_text)
    verdict, _lines, code = j4s.assess((parsed, "test"), cpu_vbmi)
    return verdict, code


class TestVersionTable(unittest.TestCase):
    # Boundary rows required by the task, plus gap/unknown rows.
    CASES = [
        # (version string, cpu, expected verdict, expected exit)
        ("17.0.5", CPU_WITH, "NOT_AFFECTED", 0),   # predates 17.0.6
        ("17.0.6", CPU_WITH, "VULNERABLE", 1),     # first affected
        ("17.0.21", CPU_WITH, "VULNERABLE", 1),    # 17.0.21 == 17.0.21.0.0
        ("17.0.21.0.3", CPU_WITH, "VULNERABLE", 1),
        ("17.0.21.0.4", CPU_WITH, "UNKNOWN", 3),   # gap: no public release
        ("17.0.21.1", CPU_WITH, "PATCHED", 0),     # Oracle fixed build
        ("17.0.22", CPU_WITH, "PATCHED", 0),       # later release
        ("21.0.13.0.3", CPU_WITH, "VULNERABLE", 1),
        ("21.0.13.1", CPU_WITH, "PATCHED", 0),
        ("21.0.14", CPU_WITH, "PATCHED", 0),
        ("25.0.5.0.3", CPU_WITH, "VULNERABLE", 1),
        ("25.0.5.1", CPU_WITH, "PATCHED", 0),
        ("27.0.1.0.3", CPU_WITH, "VULNERABLE", 1),
        ("27.0.1.1", CPU_WITH, "PATCHED", 0),
        ("11.0.33", CPU_WITH, "NOT_AFFECTED", 0),  # Java 11 not affected
        ("1.8.0_511", CPU_WITH, "NOT_AFFECTED", 0),  # standard Java 8 safe
        ("1.8.0_513", CPU_WITH, "NOT_AFFECTED", 0),  # standard Java 8 safe
        ("22.0.1", CPU_WITH, "UNKNOWN", 3),        # line not in the table
    ]

    def test_boundary_rows(self):
        for version, cpu, verdict, code in self.CASES:
            with self.subTest(version=version):
                got_verdict, got_code = verdict_for(version, cpu)
                self.assertEqual(got_verdict, verdict)
                self.assertEqual(got_code, code)

    def test_8u511b33_perf_vulnerable(self):
        # Oracle Java SE 8u511b33-perf: the ONLY affected Java 8 build.
        stderr = ('java version "1.8.0_511"\n'
                  "Java(TM) SE Runtime Environment (build 1.8.0_511-b33-perf)\n"
                  "Java HotSpot(TM) 64-Bit Server VM (build 25.511-b33-perf, "
                  "mixed mode)\n")
        parsed = j4s.parse_java_version(stderr)
        self.assertTrue(parsed["perf"])
        self.assertEqual(parsed["update"], 511)
        verdict, _lines, code = j4s.assess((parsed, "test"), True)
        self.assertEqual(verdict, "VULNERABLE")
        self.assertEqual(code, 1)

    def test_8u513_perf_patched(self):
        stderr = ('java version "1.8.0_513"\n'
                  "Java(TM) SE Runtime Environment (build 1.8.0_513-b04-perf)\n")
        parsed = j4s.parse_java_version(stderr)
        self.assertTrue(parsed["perf"])
        verdict, _lines, code = j4s.assess((parsed, "test"), True)
        self.assertEqual(verdict, "PATCHED")
        self.assertEqual(code, 0)

    def test_malformed_version_string(self):
        parsed = j4s.parse_java_version("garbage with no version line\n")
        self.assertEqual(parsed["kind"], "unknown")
        verdict, _lines, code = j4s.assess((parsed, "test"), True)
        self.assertEqual(verdict, "UNKNOWN")
        self.assertEqual(code, 3)

    def test_missing_java(self):
        verdict, _lines, code = j4s.assess((None, "no `java` on PATH"), True)
        self.assertEqual(verdict, "UNKNOWN")
        self.assertEqual(code, 3)

    def test_cpu_gate_decides(self):
        # Same affected version, three CPU states.
        for cpu, verdict, code in ((CPU_WITH, "VULNERABLE", 1),
                                   (CPU_WITHOUT, "NOT_AFFECTED", 0),
                                   ("processor : 0\n", "UNKNOWN", 3)):
            with self.subTest(cpu=cpu[:20]):
                got_verdict, got_code = verdict_for("17.0.21", cpu)
                self.assertEqual(got_verdict, verdict)
                self.assertEqual(got_code, code)

    def test_patched_ignores_cpu(self):
        # A fixed build is PATCHED even with VBMI present — and even with
        # the CPU gate unknown.
        for cpu in (CPU_WITH, CPU_WITHOUT, "processor : 0\n"):
            verdict, code = verdict_for("21.0.13.1", cpu)
            self.assertEqual((verdict, code), ("PATCHED", 0))


class TestCpuParsing(unittest.TestCase):
    def test_vbmi_present(self):
        vbmi, detail = j4s.parse_cpuinfo(CPU_WITH)
        self.assertTrue(vbmi)
        self.assertTrue(all(detail.values()))

    def test_vbmi_absent(self):
        vbmi, detail = j4s.parse_cpuinfo(CPU_WITHOUT)
        self.assertFalse(vbmi)
        self.assertFalse(detail["avx512vbmi"])
        self.assertTrue(detail["bmi2"])

    def test_no_flags_line(self):
        vbmi, detail = j4s.parse_cpuinfo("processor : 0\nvendor_id : X\n")
        self.assertIsNone(vbmi)
        self.assertIsNone(detail)

    def test_empty_cpuinfo(self):
        vbmi, detail = j4s.parse_cpuinfo("")
        self.assertIsNone(vbmi)

    def test_vbmi2_alone_is_not_vbmi(self):
        # avx512_vbmi2 must not satisfy the avx512vbmi check.
        text = "flags : avx512_vbmi2 avx512f avx512bw bmi2\n"
        vbmi, _detail = j4s.parse_cpuinfo(text)
        self.assertFalse(vbmi)


class TestDemoDeterminism(unittest.TestCase):
    def run_demo(self):
        proc = subprocess.run([sys.executable, SCRIPT, "--demo"],
                              capture_output=True, text=True, timeout=60)
        return proc.returncode, proc.stdout

    def test_demo_twice_byte_identical(self):
        code1, out1 = self.run_demo()
        code2, out2 = self.run_demo()
        self.assertEqual(out1, out2)
        self.assertEqual(code1, code2)

    def test_demo_verdicts_and_exit(self):
        code, out = self.run_demo()
        self.assertIn("Verdict: VULNERABLE", out)
        self.assertIn("Verdict: PATCHED", out)
        self.assertIn('openjdk version "17.0.21"', out)
        self.assertIn('openjdk version "21.0.13.1"', out)
        self.assertIn("Demo uses labelled fixtures only", out)
        # A vulnerable case is present, so exit 1 is the designed outcome.
        self.assertEqual(code, 1)

    def test_demo_json(self):
        proc = subprocess.run([sys.executable, SCRIPT, "--demo", "--json"],
                              capture_output=True, text=True, timeout=60)
        data = json.loads(proc.stdout)
        self.assertTrue(data["demo"])
        self.assertEqual([c["verdict"] for c in data["cases"]],
                         ["VULNERABLE", "PATCHED"])
        self.assertEqual(proc.returncode, 1)


class TestCliEndToEnd(unittest.TestCase):
    def run_cli(self, *argv, env=None):
        return subprocess.run([sys.executable, SCRIPT, *argv],
                              capture_output=True, text=True, timeout=60,
                              env=env)

    def test_fake_java_vulnerable(self):
        fake = os.path.join(ROOT, "examples", "fake-java-vulnerable.sh")
        proc = self.run_cli("--java-path", fake,
                            "--cpuinfo", os.path.join(
                                ROOT, "examples", "cpuinfo-with-vbmi.txt"))
        self.assertIn("Verdict: VULNERABLE", proc.stdout)
        self.assertEqual(proc.returncode, 1)

    def test_fake_java_patched(self):
        fake = os.path.join(ROOT, "examples", "fake-java-patched.sh")
        proc = self.run_cli("--java-path", fake,
                            "--cpuinfo", os.path.join(
                                ROOT, "examples", "cpuinfo-without-vbmi.txt"))
        self.assertIn("Verdict: PATCHED", proc.stdout)
        self.assertEqual(proc.returncode, 0)

    def test_fake_java_vulnerable_but_no_vbmi(self):
        fake = os.path.join(ROOT, "examples", "fake-java-vulnerable.sh")
        proc = self.run_cli("--java-path", fake,
                            "--cpuinfo", os.path.join(
                                ROOT, "examples", "cpuinfo-without-vbmi.txt"))
        self.assertIn("Verdict: NOT_AFFECTED", proc.stdout)
        self.assertEqual(proc.returncode, 0)

    def test_missing_java_path_is_usage_error(self):
        proc = self.run_cli("--java-path", "/nonexistent/java")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("error", proc.stderr)

    def test_no_java_on_path_is_unknown(self):
        env = dict(os.environ)
        env["PATH"] = tempfile.mkdtemp()  # empty dir: no java anywhere
        proc = self.run_cli(env=env)
        self.assertIn("Verdict: UNKNOWN", proc.stdout)
        self.assertEqual(proc.returncode, 3)

    def test_bad_flag_is_usage_error(self):
        proc = self.run_cli("--nope")
        self.assertEqual(proc.returncode, 2)

    def test_json_output(self):
        fake = os.path.join(ROOT, "examples", "fake-java-patched.sh")
        proc = self.run_cli("--java-path", fake, "--json")
        data = json.loads(proc.stdout)
        self.assertEqual(data["verdict"], "PATCHED")
        self.assertEqual(data["cve"], "CVE-2026-114938")
        self.assertEqual(proc.returncode, 0)


class TestAppsScan(unittest.TestCase):
    def test_detects_known_apps(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "opt", "keycloak-26.0.0"))
            os.makedirs(os.path.join(root, "opt", "jira-software"))
            os.makedirs(os.path.join(root, "opt", "kafka_3.7"))
            os.makedirs(os.path.join(root, "opt", "plain-app"))
            found = j4s.scan_apps(root)
            names = sorted(a["name"] for a in found)
            self.assertEqual(names, ["Apache Kafka Broker",
                                     "Atlassian Jira", "Keycloak"])
            by_name = {a["name"]: a for a in found}
            self.assertIn("pre-auth", by_name["Keycloak"]["exposure"])
            self.assertIn("after authentication",
                          by_name["Apache Kafka Broker"]["exposure"])

    def test_clean_dir_finds_nothing(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "myapp"))
            self.assertEqual(j4s.scan_apps(root), [])

    def test_apps_cli(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "confluence"))
            fake = os.path.join(ROOT, "examples", "fake-java-patched.sh")
            proc = subprocess.run(
                [sys.executable, SCRIPT, "--java-path", fake,
                 "--apps", root],
                capture_output=True, text=True, timeout=60)
            self.assertIn("Atlassian Confluence", proc.stdout)
            self.assertIn("pre-auth RCE demonstrated", proc.stdout)
            self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
