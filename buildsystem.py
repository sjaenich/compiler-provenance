import os
import sys
import re



class BuildSystem:
    def __init__(self, rootfs=None, firmware=None):
        self.type = None
        self.rootfs = rootfs
        self.firmware = firmware



    def file_contains(self, path, keywords):
        try:
            with open(path, "r", errors="ignore") as f:
                data = f.read().lower()
                return any(k in data for k in keywords)
        except FileNotFoundError:
            return False


    def detect_build_system(self):
        self.type = "Unknown"
        # 1. Check for OpenWrt markers
        if os.path.exists(os.path.join(self.rootfs, "etc/openwrt_release")):
            self.type = "OpenWrt"
            return
        if os.path.exists(os.path.join(self.rootfs, "etc/openwrt_version")):
            self.type = "OpenWrt"
            return
        if os.path.isdir(os.path.join(self.rootfs, "etc/config")):
            self.type = "OpenWrt"
            return

        # 2. Check for Yocto / Poky markers
        if self.file_contains(os.path.join(self.rootfs, "etc/os-release"), ["poky", "yocto"]):
            self.type = "Yocto / Poky"
            return
        if self.file_contains(os.path.join(self.rootfs, "etc/issue"), ["poky", "yocto"]):
            self.type = "Yocto / Poky"
            return

        # 3. Check for Buildroot markers
        if self.file_contains(os.path.join(self.rootfs, "etc/os-release"), ["buildroot"]):
            self.type = "Buildroot"
            return
        if self.file_contains(os.path.join(self.rootfs, "etc/issue"), ["buildroot"]):
            self.type = "Buildroot"
            return
        # Buildroot usually has BusyBox only, no package manager
        if (os.path.exists(os.path.join(self.rootfs, "bin/busybox")) or os.path.exists(os.path.join(self.rootfs, "sbin/busybox"))) \
            and not any(os.path.exists(os.path.join(self.rootfs, p)) for p in ["usr/bin/opkg", "usr/bin/dpkg", "usr/bin/rpm"]):
            self.type = "Likely Buildroot"
            return
        # 4. Check for Debian-based
        if os.path.exists(os.path.join(self.rootfs, "var/lib/dpkg/status")):
            self.type = "Debian/Ubuntu"
            return
        # 5. Check for RPM-based
        if os.path.isdir(os.path.join(self.rootfs, "var/lib/rpm")):
            self.type = "RPM-based (Fedora/CentOS/OpenEmbedded)"
            return
        


    def detect_monolithic_firmware(fwfile):
        sdk_markers = {
            "Nordic nRF5 SDK": [b"nrf_log", b"nrf_drv", b"nrf_delay_us"],
            "Nordic nRF Connect SDK (Zephyr)": [b"zephyr", b"ncs_version"],
            "STM32Cube": [b"stm32cube", b"hal_stm32"],
            "Espressif ESP-IDF": [b"esp_log", b"esp_idf", b"idf_version"],
            "TI SimpleLink": [b"simplelink", b"ti_drivers"],
        }

        try:
            with open(fwfile, "rb") as f:
                data = f.read()
                for sdk, patterns in sdk_markers.items():
                    for pat in patterns:
                        if re.search(pat, data, re.IGNORECASE):
                            self.type = sdk
        except FileNotFoundError:
            return "Error: file not found"

        return "Unknown"


# if __name__ == "__main__":
#     if len(sys.argv) != 3:
#         print(f"Usage: {sys.argv[0]} <mode: rootfs|firmware> <path>")
#         sys.exit(1)

#     mode = sys.argv[1]
#     target = sys.argv[2]

#     if mode == "rootfs":
#         if not os.path.isdir(target):
#             print("Error: path is not a directory")
#             sys.exit(1)
#         result = detect_build_system(target)
#         print(f"Detected build system: {result}")
#     elif mode == "firmware":
#         if not os.path.isfile(target):
#             print("Error: path is not a file")
#             sys.exit(1)
#         result = detect_monolithic_firmware(target)
#         print(f"Detected SDK: {result}")
#     else:
#         print("Mode must be either 'rootfs' or 'firmware'")
#         sys.exit(1)