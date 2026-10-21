"""setup.sh / build.sh decision logic, exercised through `setup.sh --plan` with fake distributions,
fake JDK/JRE folders and a fake SDK. Nothing is installed or downloaded.

    python3 -m unittest discover -s tools/tests -t .
"""
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SETUP = os.path.join(ROOT, "setup.sh")
BUILD = os.path.join(ROOT, "tools", "build.sh")

OS = {
    "debian12": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n',
    "ubuntu": 'PRETTY_NAME="Ubuntu 24.04 LTS"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\n',
    "mint": 'PRETTY_NAME="Linux Mint 22"\nID=linuxmint\nID_LIKE="ubuntu debian"\n',
    "fedora": 'PRETTY_NAME="Fedora Linux 41"\nID=fedora\nVERSION_ID=41\n',
    "rocky": 'ID="rocky"\nID_LIKE="rhel centos fedora"\n',
    "arch": 'NAME="Arch Linux"\nID=arch\n',
    "manjaro": "ID=manjaro\nID_LIKE=arch\n",
    "tumbleweed": 'ID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"\n',
    "alpine": "ID=alpine\n",
    "gentoo": "ID=gentoo\n",
}


def fake_java(root, name, version, jdk=True):
    """A Java home with a `release` file (what setup.sh reads) and stub binaries."""
    home = os.path.join(root, name)
    os.makedirs(os.path.join(home, "bin"))
    with open(os.path.join(home, "release"), "w") as fh:
        fh.write(f'IMPLEMENTOR="Test"\nJAVA_VERSION="{version}"\n')
    for b in ["java"] + (["javac"] if jdk else []):
        path = os.path.join(home, "bin", b)
        with open(path, "w") as fh:
            fh.write("#!/bin/sh\nexit 0\n")
        os.chmod(path, 0o755)
    return home


def fake_sdk(root, packages=("platforms/android-34", "build-tools/34.0.0", "platform-tools")):
    sdk = os.path.join(root, "sdk")
    for p in packages:
        os.makedirs(os.path.join(sdk, p))
        open(os.path.join(sdk, p, "package.xml"), "w").close()
    bin_dir = os.path.join(sdk, "cmdline-tools", "latest", "bin")
    os.makedirs(bin_dir)
    with open(os.path.join(bin_dir, "sdkmanager"), "w") as fh:
        fh.write("#!/bin/sh\n")
    os.chmod(os.path.join(bin_dir, "sdkmanager"), 0o755)
    return sdk


class SetupPlan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fta_setup_")
        self.jvm = os.path.join(self.tmp, "jvm")
        os.makedirs(self.jvm)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_setup(self, distro="debian12", *args, env_extra=None):
        osr = os.path.join(self.tmp, "os-release")
        with open(osr, "w") as fh:
            fh.write(OS[distro])
        env = {k: v for k, v in os.environ.items() if k not in ("JAVA_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT")}
        self.local_props = os.path.join(self.tmp, "local.properties")   # never the repo's real one
        env.update({"FTA_OS_RELEASE": osr, "FTA_JVM_DIRS": self.jvm, "FTA_IGNORE_PATH_JDK": "1", "HOME": self.home,
                    "NO_COLOR": "1", "FTA_LOCAL_PROPERTIES": self.local_props})
        env.update(env_extra or {})
        p = subprocess.run(["bash", SETUP, *args], capture_output=True, text=True, env=env, cwd=self.tmp)
        return p

    def plan(self, distro="debian12", *args, **kw):
        p = self.run_setup(distro, "--plan", *args, **kw)
        self.assertEqual(p.returncode, 0, p.stderr)
        return dict(line.split("=", 1) for line in p.stdout.splitlines() if "=" in line)

    # --- the reported case: Debian with JDK 11 + Java 17 present only as a JRE
    def test_debian_jre17_only(self):
        fake_java(self.jvm, "java-11-openjdk-amd64", "11.0.24")
        jre17 = fake_java(self.jvm, "java-17-openjdk-amd64", "17.0.12", jdk=False)
        os.symlink(jre17, os.path.join(self.jvm, "java-1.17.0-openjdk-amd64"))      # Debian alias, must be skipped
        d = self.plan("debian12")
        self.assertEqual(d["pkg_manager"], "apt")
        self.assertEqual(d["jdk"], "none")
        self.assertEqual(d["jre_only"], jre17)
        self.assertEqual(d["jdk_action"], "install-package:openjdk-17-jdk-headless|download-temurin:17.0.13+11")

    def test_debian_jdk17_present(self):
        fake_java(self.jvm, "java-11-openjdk-amd64", "11.0.24")
        jdk17 = fake_java(self.jvm, "java-17-openjdk-amd64", "17.0.12")
        d = self.plan("debian12")
        self.assertEqual((d["jdk"], d["jdk_action"]), (jdk17, "use"))

    def test_java_home_wins_and_old_version_strings(self):
        fake_java(self.jvm, "java-8", "1.8.0_392")                 # must parse as 8, not 1
        mine = fake_java(self.tmp, "custom-jdk17", "17.0.9")
        d = self.plan("ubuntu", env_extra={"JAVA_HOME": mine})
        self.assertEqual(d["jdk"], mine)

    def test_package_managers(self):
        expect = {"ubuntu": ("apt", "openjdk-17-jdk-headless"), "mint": ("apt", "openjdk-17-jdk-headless"),
                  "fedora": ("dnf", "java-17-openjdk-devel"), "rocky": ("dnf", "java-17-openjdk-devel"),
                  "arch": ("pacman", "jdk17-openjdk"), "manjaro": ("pacman", "jdk17-openjdk"),
                  "tumbleweed": ("zypper", "java-17-openjdk-devel")}
        for distro, (pm, pkg) in expect.items():
            d = self.plan(distro)
            self.assertEqual(d["pkg_manager"], pm, distro)
            self.assertTrue(d["jdk_action"].startswith(f"install-package:{pkg}|"), (distro, d["jdk_action"]))
            self.assertEqual(d["pm_supported"], "yes")

    def test_unsupported_distros(self):
        d = self.plan("alpine")
        self.assertEqual((d["pkg_manager"], d["pm_supported"]), ("apk", "no"))
        d = self.plan("gentoo")
        self.assertEqual((d["pkg_manager"], d["pm_supported"]), ("none", "no"))
        self.assertEqual(d["jdk_action"], "download-temurin:17.0.13+11")
        p = self.run_setup("alpine", "--no-build")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("musl", p.stderr)

    def test_sdk_resolution(self):
        sdk = fake_sdk(self.tmp)
        d = self.plan("debian12", "--sdk", sdk)
        self.assertEqual((d["sdk_dir"], d["cmdline_tools"], d["sdk_missing"]), (sdk, "present", ""))
        d = self.plan("debian12", env_extra={"ANDROID_HOME": sdk})
        self.assertEqual(d["sdk_dir"], sdk)
        d = self.plan("debian12")
        self.assertEqual(d["sdk_dir"], os.path.join(self.home, "Android", "Sdk"))
        with open(self.local_props, "w") as fh:                     # android/local.properties is honoured
            fh.write("# generated\nsdk.dir=/opt/sdk-from-local-properties\n")
        self.assertEqual(self.plan("debian12")["sdk_dir"], "/opt/sdk-from-local-properties")
        os.remove(self.local_props)
        self.assertEqual(d["sdk_missing"], "platforms;android-34 build-tools;34.0.0 platform-tools")
        self.assertEqual(d["cmdline_tools"], "install:11076708")

    def test_partial_sdk_and_no_adb(self):
        sdk = fake_sdk(self.tmp, packages=("platforms/android-34",))
        d = self.plan("debian12", "--sdk", sdk, "--no-adb")
        self.assertEqual(d["sdk_missing"], "build-tools;34.0.0")

    def test_check_mode_exit_codes(self):
        sdk = fake_sdk(self.tmp)
        fake_java(self.jvm, "jdk17", "17.0.12")
        p = self.run_setup("debian12", "--check", "--sdk", sdk)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("ready to build", p.stdout)
        p = self.run_setup("debian12", "--check")                      # no SDK in the fake HOME
        self.assertEqual(p.returncode, 1)

    def test_bad_arguments(self):
        self.assertEqual(self.run_setup("debian12", "--nope").returncode, 2)
        jre = fake_java(self.tmp, "jre17", "17.0.1", jdk=False)
        p = self.run_setup("debian12", "--plan", "--jdk", jre)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("needs bin/javac", p.stderr)

    def test_help(self):
        p = self.run_setup("debian12", "--help")
        self.assertEqual(p.returncode, 0)
        self.assertIn("--accept-licenses", p.stdout)


class BuildGuards(unittest.TestCase):
    def run_build(self, java_home):
        env = dict(os.environ, JAVA_HOME=java_home, FTA_ENV="/dev/null")
        env.pop("ANDROID_HOME", None)
        return subprocess.run(["bash", BUILD, "--skip-tests"], capture_output=True, text=True, env=env)

    def test_refuses_wrong_java(self):
        tmp = tempfile.mkdtemp()
        p = self.run_build(fake_java(tmp, "jdk11", "11.0.2"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("pinned to 17", p.stderr)
        p = self.run_build(fake_java(tmp, "jre17", "17.0.2", jdk=False))
        self.assertIn("no javac", p.stderr)
        shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
