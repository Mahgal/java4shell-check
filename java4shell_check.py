#!/usr/bin/env python3
"""java4shell-check: are you exposed to Java4Shell (CVE-2026-114938)?

Defensive checker only. Stdlib only, zero network calls.

Java4Shell is a memory-corruption flaw in OpenJDK's AVX-512 VBMI Base64
decoder: a malformed Base64 string ending with an extra ``=`` overflows the
output buffer. Calif disclosed it on 2026-11-17 (CVSS 4.0 9.2; Oracle
CVSS 3.1 8.1) and demonstrated pre-auth RCE against default installs of
Keycloak, Jira, Confluence, Artifactory, Jenkins and PingFederate.

Three conditions must ALL hold for a host to be exposed:

  1. Java version in an affected range (see VERSION_TABLE below),
  2. x86-64 CPU with AVX-512 VBMI (flag ``avx512_vbmi`` in /proc/cpuinfo),
  3. attacker-controlled input reaching the Base64 decoder (any Java app
     that decodes Base64 from the network — auth, file upload, TLS, ...).

This tool checks (1) and (2) and reports an honest verdict. It never
sends a payload, never scans the network, and contains no exploit code.

Usage:
    python3 java4shell_check.py [--java-path PATH] [--cpuinfo PATH]
                                [--json] [--apps DIR] [--demo]

Exit codes:
    0  PATCHED or NOT_AFFECTED
    1  VULNERABLE (by design: use as a CI gate)
    2  usage error (bad flag, unreadable --java-path/--cpuinfo/--apps path)
    3  UNKNOWN (no java found, unparseable version, or CPU unknown while
       the version is in an affected range)
"""

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys

CVE = "CVE-2026-114938"
NICKNAME = "Java4Shell"

# Affected / fixed version table, from the Oracle advisory and the Calif
# write-up as summarised by Censys (2026-11-17). Each entry is
# (major, first_affected, last_affected, first_fixed); versions are tuples
# compared after padding with zeros. "None" for first_affected means the
# whole line up to last_affected is affected (no lower bound published).
# Versions strictly between last_affected and first_fixed have no public
# release and are reported UNKNOWN rather than guessed.
VERSION_TABLE = {
    17: ((17, 0, 6), (17, 0, 21, 0, 3), (17, 0, 21, 1)),
    21: (None, (21, 0, 13, 0, 3), (21, 0, 13, 1)),
    25: (None, (25, 0, 5, 0, 3), (25, 0, 5, 1)),
    27: (None, (27, 0, 1, 0, 3), (27, 0, 1, 1)),
}

# Fixed releases, for the "upgrade to" advice.
FIXED_RELEASES = {
    17: "17.0.21.1 (Oracle) / 17.0.21.1.2 (Corretto)",
    21: "21.0.13.1 (Oracle) / 21.0.13.1.2 (Corretto)",
    25: "25.0.5.1 (Oracle) / 25.0.5.1.2 (Corretto)",
    27: "27.0.1.1 (Oracle) / 27.0.1.1.4 (Corretto)",
}

# Calif: on Linux all four flags must appear in /proc/cpuinfo for the
# vulnerable path to be reachable. avx512_vbmi is the distinguishing one;
# the tool gates on it and reports the other three for transparency.
REQUIRED_FLAGS = ("avx512f", "avx512bw", "avx512vbmi", "bmi2")

# Apps Calif reports pre-auth RCE against (default configs), and apps where
# the demonstrated path needed authentication. Presence of an install dir
# is NOT proof of exploitability — only that the app is installed.
PRE_AUTH_APPS = {
    "keycloak": "Keycloak",
    "jira": "Atlassian Jira",
    "confluence": "Atlassian Confluence",
    "artifactory": "JFrog Artifactory",
    "jenkins": "Jenkins",
    "pingfederate": "PingFederate",
}
AUTH_REQUIRED_APPS = {
    "kafka": "Apache Kafka Broker",
    "solr": "Apache Solr",
    "elasticsearch": "Elasticsearch",
    "gerrit": "Gerrit",
    "spinnaker": "Spinnaker",
}
KNOWN_APPS = dict(PRE_AUTH_APPS)
KNOWN_APPS.update(AUTH_REQUIRED_APPS)

# ---------------------------------------------------------------------------
# Version parsing
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r'version\s+"([^"]+)"')
_LEGACY_RE = re.compile(r"^1\.(\d+)\.(\d+)_(\d+)")
_MODERN8_RE = re.compile(r"^8u(\d+)")


def _parse_numbered(version_str):
    """'17.0.21.0.3' / '21.0.13+9' -> (17, 0, 21, 0, 3). None if unparseable."""
    core = re.split(r"[+-]", version_str, maxsplit=1)[0]
    parts = core.split(".")
    nums = []
    for part in parts:
        if not part.isdigit():
            return None
        nums.append(int(part))
    return tuple(nums) if nums else None


def _pad(version, length=5):
    return tuple(version) + (0,) * (length - len(version))


def parse_java_version(stderr_text):
    """Parse `java -version` stderr.

    Returns dict with keys:
      raw: the quoted version string (or None),
      kind: 'modern' | 'legacy8' | 'unknown',
      version: int tuple (modern) or None,
      update: int update number for Java 8 (e.g. 511) or None,
      perf: True if this looks like Oracle's 8 Enterprise Performance Pack,
      display: short display string for output.
    """
    match = _VERSION_RE.search(stderr_text or "")
    raw = match.group(1) if match else None
    vendor_match = re.search(r"^\s*(\S+)\s+version\s+\"",
                             stderr_text or "", re.M)
    vendor = vendor_match.group(1) if vendor_match else "java"
    lowered = (stderr_text or "").lower()
    perf = "perf" in lowered or (raw is not None and "perf" in raw.lower())
    if raw is None:
        return {"raw": None, "kind": "unknown", "version": None,
                "update": None, "perf": perf, "display": None,
                "vendor": vendor}
    legacy = _LEGACY_RE.match(raw)
    if legacy:
        # '1.8.0_511' -> Java 8, update 511
        return {"raw": raw, "kind": "legacy8", "version": (8,),
                "update": int(legacy.group(3)), "perf": perf,
                "display": "1.8.0_%d" % int(legacy.group(3)),
                "vendor": vendor}
    modern8 = _MODERN8_RE.match(raw)
    if modern8:
        # '8u511b33-perf' style
        return {"raw": raw, "kind": "legacy8", "version": (8,),
                "update": int(modern8.group(1)), "perf": True,
                "display": raw, "vendor": vendor}
    version = _parse_numbered(raw)
    if version is None:
        return {"raw": raw, "kind": "unknown", "version": None,
                "update": None, "perf": perf, "display": raw,
                "vendor": vendor}
    return {"raw": raw, "kind": "modern", "version": version,
            "update": None, "perf": perf, "display": raw, "vendor": vendor}


def classify_version(parsed):
    """Classify a parsed version. Returns (status, reason) where status is
    'affected' | 'patched' | 'not_affected' | 'unknown'."""
    if parsed["kind"] == "unknown":
        return "unknown", "could not parse a version number from `java -version` output"
    if parsed["kind"] == "legacy8":
        update = parsed["update"]
        if parsed["perf"]:
            # Oracle Java SE 8 Enterprise Performance Pack only.
            if update == 511:
                return "affected", ("Oracle Java SE 8u511b33-perf is listed "
                                    "affected; fixed in 8u513-perf")
            if update >= 513:
                return "patched", ("Java 8 Performance Pack 8u513+ "
                                    "is the fixed build")
            return "unknown", ("Java 8 Performance Pack build 8u%d is not "
                               "in the published affected/fixed table" % update)
        return "not_affected", ("standard Java 8 is not affected "
                                "(only the 8u511b33-perf Performance Pack build is)")
    version = parsed["version"]
    major = version[0]
    if major == 11:
        return "not_affected", "Java 11 is not affected (Oracle lists no Java 11 build)"
    entry = VERSION_TABLE.get(major)
    if entry is None:
        return "unknown", ("Java %d is not covered by the published "
                           "affected/fixed table (17/21/25/27)" % major)
    first_affected, last_affected, first_fixed = entry
    padded = _pad(version)
    if padded >= _pad(first_fixed):
        return "patched", "Java %s is at or above the fixed release %s" % (
            parsed["display"], ".".join(str(x) for x in first_fixed))
    if first_affected is not None and padded < _pad(first_affected):
        return "not_affected", ("Java %s predates the affected range "
                                "(first affected: %s)"
                                % (parsed["display"],
                                   ".".join(str(x) for x in first_affected)))
    if padded <= _pad(last_affected):
        return "affected", ("Java %s is in the affected range "
                            "(up to %s)"
                            % (parsed["display"],
                               ".".join(str(x) for x in last_affected)))
    return "unknown", ("Java %s falls between the last known-affected "
                       "build %s and the first known-fixed build %s; "
                       "no public release sits there — upgrade to %s"
                       % (parsed["display"],
                          ".".join(str(x) for x in last_affected),
                          ".".join(str(x) for x in first_fixed),
                          FIXED_RELEASES[major]))


# ---------------------------------------------------------------------------
# CPU flags
# ---------------------------------------------------------------------------

def parse_cpuinfo(text):
    """Parse /proc/cpuinfo text. Returns (vbmi_present, flags_dict) where
    flags_dict maps each of REQUIRED_FLAGS to True/False, or (None, None)
    if no flags line was found."""
    flags = set()
    found = False
    for line in (text or "").splitlines():
        if line.startswith("flags"):
            _, _, rest = line.partition(":")
            flags = set(rest.split())
            found = True
            break
    if not found:
        return None, None
    detail = {flag: (flag in flags) for flag in REQUIRED_FLAGS}
    return detail["avx512vbmi"], detail


def read_cpuinfo(path):
    """Returns (vbmi, detail, source_note) or raises OSError."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    vbmi, detail = parse_cpuinfo(text)
    return vbmi, detail, path


# ---------------------------------------------------------------------------
# java -version
# ---------------------------------------------------------------------------

def run_java_version(java_path):
    """Run `<java_path> -version`, return (returncode, stderr_text)."""
    proc = subprocess.run([java_path, "-version"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=30)
    return proc.returncode, proc.stderr


def find_java(explicit_path):
    """Resolve the java binary to run. Returns (path, error_message)."""
    if explicit_path:
        if not os.path.isfile(explicit_path):
            return None, "no such file: %s" % explicit_path
        if not os.access(explicit_path, os.X_OK):
            return None, "not executable: %s" % explicit_path
        return explicit_path, None
    found = shutil.which("java")
    if found:
        return found, None
    return None, "no `java` on PATH (pass --java-path PATH to point at one)"


# ---------------------------------------------------------------------------
# --apps scan
# ---------------------------------------------------------------------------

def scan_apps(root):
    """Walk `root` (max depth 3) for known app install dirs.

    Returns a list of dicts: {token, name, exposure, path}."""
    found = []
    root = os.path.abspath(root)
    for dirpath, dirnames, _filenames in os.walk(root):
        depth = dirpath[len(root):].count(os.sep)
        if depth > 3:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for dirname in list(dirnames):
            token = re.sub(r"[-_]", "", dirname.lower())
            for marker, name in KNOWN_APPS.items():
                if marker in token:
                    exposure = ("pre-auth RCE demonstrated by Calif"
                                if marker in PRE_AUTH_APPS else
                                "RCE demonstrated after authentication")
                    found.append({"token": marker, "name": name,
                                  "exposure": exposure,
                                  "path": os.path.join(dirpath, dirname)})
                    break
    found.sort(key=lambda item: (item["name"], item["path"]))
    return found


# ---------------------------------------------------------------------------
# Verdict assembly
# ---------------------------------------------------------------------------

def assess(java_info, cpu_vbmi):
    """Combine version classification and CPU gate into a verdict.

    java_info: (parsed, source_note) or (None, reason) when java is missing.
    cpu_vbmi: True / False / None.
    Returns (verdict, detail_lines, exit_code)."""
    parsed, java_note = java_info
    if parsed is None:
        return ("UNKNOWN",
                ["Java: not found — %s" % java_note,
                 "Cannot assess the version gate without a Java runtime."],
                3)
    status, reason = classify_version(parsed)
    java_line = ('Java: %s version "%s" (%s)'
                 % (parsed.get("vendor", "java"), parsed["raw"], java_note)
                 if parsed.get("raw") else
                 "Java: %s (%s)" % (parsed["display"], java_note))
    lines = [java_line, reason]
    if status == "patched":
        return "PATCHED", lines + [
            "Fixed build — the AVX-512 VBMI Base64 decoder flaw is closed.",
            "Restart every JVM so the fixed build is the one running."], 0
    if status == "not_affected":
        return "NOT_AFFECTED", lines + [
            "This Java line is not affected by %s." % CVE], 0
    if status == "unknown":
        return "UNKNOWN", lines + [
            "Version not covered by the published table — upgrade to a "
            "known-fixed build to be certain."], 3
    # status == "affected": the CPU gate decides.
    if cpu_vbmi is True:
        major = parsed["version"][0]
        return "VULNERABLE", lines + [
            "CPU has AVX-512 VBMI, so the vulnerable decoder path is reachable.",
            "Fix: upgrade to %s." % FIXED_RELEASES.get(major, "a fixed build"),
            "Mitigation until patched: -XX:-UseBASE64Intrinsics "
            "(or -XX:UseAVX=2 on x86-64 only)."], 1
    if cpu_vbmi is False:
        return "NOT_AFFECTED", lines + [
            "CPU lacks AVX-512 VBMI, so the vulnerable decoder path cannot run.",
            "No patch needed for %s on this host." % CVE], 0
    return "UNKNOWN", lines + [
        "Version is in the affected range, but the CPU gate is unknown "
        "(no /proc/cpuinfo on this OS, or no flags line).",
        "Check the CPU for AVX-512 VBMI by hand, or upgrade to a "
        "known-fixed build."], 3


def cpu_line(cpu_vbmi, detail, source_note):
    """One-line human summary of the CPU gate."""
    if cpu_vbmi is None:
        return "CPU: unknown (%s)" % source_note
    flags_text = ", ".join("%s: %s" % (flag, "yes" if detail[flag] else "no")
                           for flag in REQUIRED_FLAGS)
    state = "present" if cpu_vbmi else "absent"
    return "CPU: %s, AVX-512 VBMI %s (%s; from %s)" % (
        platform.machine() or "unknown-arch", state, flags_text, source_note)


# ---------------------------------------------------------------------------
# Demo fixtures (labelled, deterministic — no host data, no timestamps)
# ---------------------------------------------------------------------------

DEMO_CASES = [
    {
        "label": "vulnerable fixture — openjdk 17.0.21 on x86-64 with AVX-512 VBMI",
        "java_stderr": (
            'openjdk version "17.0.21" 2025-10-21\n'
            "OpenJDK Runtime Environment (build 17.0.21+9)\n"
            "OpenJDK 64-Bit Server VM (build 17.0.21+9, mixed mode, sharing)\n"
        ),
        "cpuinfo": (
            "processor\t: 0\n"
            "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge "
            "mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm "
            "pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon "
            "pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf "
            "tsc_known_freq pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 "
            "ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe "
            "popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm "
            "abm 3dnowprefetch cpuid_fault epb invpcid_single pti ssbd "
            "ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid ept_ad "
            "fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx "
            "rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 "
            "xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window "
            "hwp_epp hwp_pkg_req avx512f avx512dq rdseed adx smap "
            "clflushopt avx512cd avx512bw avx512vl avx512vbmi avx512_vbmi2 "
            "gfni vaes vpclmulqdq avx512_vnni avx512_bitalg avx512_vpopcntdq\n"
        ),
    },
    {
        "label": "patched fixture — openjdk 21.0.13.1 on x86-64 with AVX-512 VBMI",
        "java_stderr": (
            'openjdk version "21.0.13.1" 2026-11-17\n'
            "OpenJDK Runtime Environment (build 21.0.13.1+1)\n"
            "OpenJDK 64-Bit Server VM (build 21.0.13.1+1, mixed mode, sharing)\n"
        ),
        "cpuinfo": (
            "processor\t: 0\n"
            "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge "
            "mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm "
            "pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon "
            "pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf "
            "tsc_known_freq pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 "
            "ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe "
            "popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm "
            "abm 3dnowprefetch cpuid_fault epb invpcid_single pti ssbd "
            "ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid ept_ad "
            "fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx "
            "rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 "
            "xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window "
            "hwp_epp hwp_pkg_req avx512f avx512dq rdseed adx smap "
            "clflushopt avx512cd avx512bw avx512vl avx512vbmi avx512_vbmi2 "
            "gfni vaes vpclmulqdq avx512_vnni avx512_bitalg avx512_vpopcntdq\n"
        ),
    },
]


def run_demo(as_json):
    """Run the labelled fixtures. Returns (text, exit_code)."""
    cases = []
    for index, case in enumerate(DEMO_CASES, start=1):
        parsed = parse_java_version(case["java_stderr"])
        cpu_vbmi, detail = parse_cpuinfo(case["cpuinfo"])
        verdict, lines, _code = assess((parsed, "fixture"), cpu_vbmi)
        cases.append({
            "label": case["label"],
            "java": parsed["display"],
            "cpu_vbmi": cpu_vbmi,
            "cpu_flags": detail,
            "verdict": verdict,
            "detail": lines,
        })
    if as_json:
        return json.dumps({"demo": True, "cases": cases}, indent=2) + "\n", \
            1 if any(c["verdict"] == "VULNERABLE" for c in cases) else 0
    out = []
    for index, case in enumerate(cases, start=1):
        out.append("[demo %d/%d] %s" % (index, len(cases), case["label"]))
        out.append(case["detail"][0])
        out.append(cpu_line(case["cpu_vbmi"], case["cpu_flags"], "fixture"))
        out.append("Verdict: %s" % case["verdict"])
        for line in case["detail"][1:]:
            out.append("  " + line)
        out.append("")
    out.append("Demo uses labelled fixtures only — not this machine.")
    out.append("Run without --demo to check this machine.")
    return "\n".join(out) + "\n", \
        1 if any(c["verdict"] == "VULNERABLE" for c in cases) else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="java4shell_check.py",
        description="Check whether this host is exposed to Java4Shell "
                    "(CVE-2026-114938). Defensive checker only: stdlib, "
                    "no network, no payloads.")
    parser.add_argument("--java-path", metavar="PATH",
                        help="path to a java binary to check "
                             "(default: `java` on PATH)")
    parser.add_argument("--cpuinfo", metavar="PATH", default="/proc/cpuinfo",
                        help="path to a cpuinfo file (default: /proc/cpuinfo)")
    parser.add_argument("--json", action="store_true",
                        help="print machine-readable JSON instead of text")
    parser.add_argument("--apps", metavar="DIR",
                        help="also scan DIR for install dirs of apps Calif "
                             "demonstrated RCE against (Keycloak, Jira, "
                             "Confluence, Artifactory, Jenkins, "
                             "PingFederate, Kafka, Solr, Elasticsearch, "
                             "Gerrit, Spinnaker)")
    parser.add_argument("--demo", action="store_true",
                        help="run the labelled fixtures (one vulnerable, "
                             "one patched); deterministic, no host data")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.demo:
        text, code = run_demo(args.json)
        sys.stdout.write(text)
        return code

    # --- CPU gate ---
    try:
        cpu_vbmi, cpu_detail, cpu_source = read_cpuinfo(args.cpuinfo)
        cpu_note = cpu_source
    except OSError as exc:
        if args.cpuinfo == "/proc/cpuinfo":
            cpu_vbmi, cpu_detail = None, None
            cpu_note = "no /proc/cpuinfo on this OS — CPU gate unknown"
        else:
            print("error: cannot read --cpuinfo %s: %s"
                  % (args.cpuinfo, exc), file=sys.stderr)
            return 2

    # --- Java version gate ---
    java_path, error = find_java(args.java_path)
    if java_path is None:
        if args.java_path:
            print("error: %s" % error, file=sys.stderr)
            return 2
        java_info = (None, error)
    else:
        try:
            _rc, stderr_text = run_java_version(java_path)
        except (OSError, subprocess.SubprocessError) as exc:
            print("error: cannot run %s -version: %s" % (java_path, exc),
                  file=sys.stderr)
            return 2
        parsed = parse_java_version(stderr_text)
        java_info = (parsed, "%s -version" % java_path)

    verdict, lines, code = assess(java_info, cpu_vbmi)

    # --- optional --apps scan ---
    apps = None
    if args.apps:
        if not os.path.isdir(args.apps):
            print("error: --apps path is not a directory: %s" % args.apps,
                  file=sys.stderr)
            return 2
        apps = scan_apps(args.apps)

    if args.json:
        result = {
            "cve": CVE,
            "nickname": NICKNAME,
            "verdict": verdict,
            "java": ({
                "display": java_info[0]["display"],
                "raw": java_info[0]["raw"],
                "source": java_info[1],
            } if java_info[0] else {"display": None, "source": java_info[1]}),
            "cpu": {
                "arch": platform.machine(),
                "avx512_vbmi": cpu_vbmi,
                "flags": cpu_detail,
                "source": cpu_note,
            },
            "detail": lines,
        }
        if apps is not None:
            result["apps"] = apps
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
        return code

    for line in lines[:1]:
        print(line)
    print(cpu_line(cpu_vbmi, cpu_detail, cpu_note))
    print("Verdict: %s" % verdict)
    for line in lines[1:]:
        print("  " + line)
    if apps is not None:
        print("")
        if apps:
            print("Known Java4Shell-exposed apps found under %s:" % args.apps)
            for app in apps:
                print("  - %s (%s) — %s" % (app["name"], app["exposure"],
                                             app["path"]))
            print("  Presence of an install dir does not prove it runs on "
                  "an affected JVM;")
            print("  check the JVM that app actually uses.")
        else:
            print("No known Java4Shell-exposed app install dirs found under "
                  "%s." % args.apps)
    return code


if __name__ == "__main__":
    sys.exit(main())
