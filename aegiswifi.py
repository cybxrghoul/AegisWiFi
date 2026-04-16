import platform
import re
import shutil
import subprocess
import sys
from typing import List, Dict
from dataclasses import dataclass, field
from typing import List

from colorama import Fore, Style, init

init(autoreset=True)


@dataclass
class WifiNetwork:
    ssid: str
    bssid: str
    signal: int
    channel: str
    security: str
    score: int = 0
    assessment: str = ""
    warnings: List[str] = field(default_factory=list)


def print_banner() -> None:
    print(Fore.CYAN + "=" * 55)
    print(Fore.CYAN + "               AegisWiFi Security Analyzer")
    print(Fore.CYAN + "=" * 55)
    print(Fore.WHITE + "Defensive wireless network risk assessment tool\n")


def check_dependency(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None


def run_windows_scan() -> str:
    """
    Run a WiFi scan on Windows using netsh.
    """
    if not check_dependency("netsh"):
        raise RuntimeError("Required dependency 'netsh' was not found.")

    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8",
            errors="replace",
        )
        if "Access is denied" in result.stdout:
            raise RuntimeError(
                "Windows denied WiFi scan access. Enable Location Services and allow "
                "desktop apps to access location, then try again."
            )
        return result.stdout
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else str(exc)
        raise RuntimeError(f"Windows WiFi scan failed: {stderr}") from exc


def run_linux_scan() -> str:
    """
    Run a WiFi scan on Linux using nmcli.
    Escapes ':' in fields, which nmcli represents as '\\:'.
    """
    if not check_dependency("nmcli"):
        raise RuntimeError(
            "Required dependency 'nmcli' was not found. Install NetworkManager tools."
        )

    try:
        result = subprocess.run(
            [
                "nmcli",
                "-t",
                "--escape",
                "yes",
                "-f",
                "SSID,BSSID,SIGNAL,CHAN,SECURITY",
                "device",
                "wifi",
                "list",
            ],
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8",
            errors="replace",
        )
        return result.stdout
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else str(exc)
        raise RuntimeError(f"Linux WiFi scan failed: {stderr}") from exc


def split_nmcli_escaped(line: str) -> List[str]:
    """
    Split nmcli colon-delimited output while respecting escaped colons '\\:'.
    """
    fields = []
    current = []
    escape = False

    for char in line:
        if escape:
            current.append(char)
            escape = False
        elif char == "\\":
            escape = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)

    fields.append("".join(current))
    return fields


def parse_linux_scan(raw_output: str) -> List[WifiNetwork]:
    networks: List[WifiNetwork] = []

    for raw_line in raw_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        parts = split_nmcli_escaped(line)

        if len(parts) < 5:
            continue

        ssid, bssid, signal_text, channel, security = parts[:5]

        ssid = ssid.replace("\\:", ":").strip() or "<Hidden>"
        bssid = bssid.replace("\\:", ":").strip() or "Unknown"

        try:
            signal = int(signal_text.strip())
        except ValueError:
            signal = 0

        channel = channel.strip() or "Unknown"
        security = security.strip() or "OPEN"

        networks.append(
            WifiNetwork(
                ssid=ssid,
                bssid=bssid,
                signal=signal,
                channel=channel,
                security=security,
            )
        )

    return networks


def parse_windows_scan(raw_output: str) -> List[WifiNetwork]:
    networks: List[WifiNetwork] = []

    current_ssid = None
    current_security = "Unknown"
    current_auth = None
    current_encrypt = None

    lines = raw_output.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i].strip()

        if not line:
            i += 1
            continue

        ssid_match = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line, re.IGNORECASE)
        if ssid_match:
            current_ssid = ssid_match.group(1).strip() or "<Hidden>"
            current_security = "Unknown"
            current_auth = None
            current_encrypt = None
            i += 1
            continue

        auth_match = re.match(r"^Authentication\s*:\s*(.*)$", line, re.IGNORECASE)
        if auth_match:
            current_auth = auth_match.group(1).strip()
            i += 1
            continue

        encrypt_match = re.match(r"^Encryption\s*:\s*(.*)$", line, re.IGNORECASE)
        if encrypt_match:
            current_encrypt = encrypt_match.group(1).strip()
            if current_auth and current_encrypt:
                current_security = f"{current_auth} / {current_encrypt}"
            elif current_auth:
                current_security = current_auth
            elif current_encrypt:
                current_security = current_encrypt
            i += 1
            continue

        bssid_match = re.match(r"^BSSID\s+\d+\s*:\s*(.*)$", line, re.IGNORECASE)
        if bssid_match:
            bssid = bssid_match.group(1).strip() or "Unknown"
            signal = 0
            channel = "Unknown"

            j = i + 1
            while j < len(lines):
                follow = lines[j].strip()

                if re.match(r"^BSSID\s+\d+\s*:", follow, re.IGNORECASE):
                    break
                if re.match(r"^SSID\s+\d+\s*:", follow, re.IGNORECASE):
                    break

                signal_match = re.match(r"^Signal\s*:\s*(\d+)%$", follow, re.IGNORECASE)
                if signal_match:
                    try:
                        signal = int(signal_match.group(1))
                    except ValueError:
                        signal = 0

                channel_match = re.match(r"^Channel\s*:\s*(.*)$", follow, re.IGNORECASE)
                if channel_match:
                    channel = channel_match.group(1).strip() or "Unknown"

                j += 1

            networks.append(
                WifiNetwork(
                    ssid=current_ssid or "<Hidden>",
                    bssid=bssid,
                    signal=signal,
                    channel=channel,
                    security=current_security,
                )
            )

            i = j
            continue

        i += 1

    return networks


def get_networks() -> List[WifiNetwork]:
    system_name = platform.system()

    if system_name == "Windows":
        raw_output = run_windows_scan()
        return parse_windows_scan(raw_output)

    if system_name == "Linux":
        raw_output = run_linux_scan()
        return parse_linux_scan(raw_output)

    raise RuntimeError(f"Unsupported operating system: {system_name}")


def signal_bar(signal: int) -> str:
    if signal >= 80:
        return "██████████"
    if signal >= 60:
        return "███████░░░"
    if signal >= 40:
        return "█████░░░░░"
    if signal >= 20:
        return "███░░░░░░░"
    return "█░░░░░░░░░"

def normalize_security_text(security: str) -> str:
    """
    Normalize security text for more reliable scoring across Windows/Linux outputs.
    """
    return security.strip().upper()


def assess_network_security(net: WifiNetwork) -> None:
    """
    Assign score, assessment, and warnings to a single network.
    """
    security = normalize_security_text(net.security)
    warnings: List[str] = []
    score = 50  # neutral baseline

    # Security / authentication scoring
    if "OPEN" in security or "NONE" in security:
        score = 15
        warnings.append("Open network detected")
    elif "WEP" in security:
        score = 25
        warnings.append("Weak legacy encryption (WEP)")
    elif "WPA3" in security:
        score = 92
    elif "WPA2" in security:
        score = 78
    elif "WPA" in security:
        score = 55
        warnings.append("Legacy WPA detected")
    else:
        score = 45
        warnings.append("Unknown or uncommon security configuration")

    # Hidden SSID
    if not net.ssid.strip() or net.ssid.strip() == "<Hidden>":
        score -= 5
        warnings.append("Hidden SSID detected")

    # Weak signal can mean unstable/less trustworthy scan confidence
    if net.signal < 30:
        score -= 10
        warnings.append("Very weak signal")
    elif net.signal < 50:
        score -= 5
        warnings.append("Weak signal")

    # Clamp score
    score = max(0, min(score, 100))

    # Final assessment
    if score >= 85:
        assessment = "Highly Secure"
    elif score >= 70:
        assessment = "Moderately Secure"
    elif score >= 45:
        assessment = "Needs Attention"
    else:
        assessment = "High Risk"

    net.score = score
    net.assessment = assessment
    net.warnings = warnings


def analyze_networks(networks: List[WifiNetwork]) -> None:
    """
    Analyze all detected networks in place.
    """
    for net in networks:
        assess_network_security(net)


def detect_duplicate_ssids(networks: List[WifiNetwork]) -> Dict[str, List[WifiNetwork]]:
    """
    Group networks by SSID and return only those with more than one BSSID.
    Hidden SSIDs are ignored for evil-twin style duplicate checks.
    """
    grouped: Dict[str, List[WifiNetwork]] = {}

    for net in networks:
        ssid = net.ssid.strip()
        if not ssid or ssid == "<Hidden>":
            continue
        grouped.setdefault(ssid, []).append(net)

    return {
        ssid: members
        for ssid, members in grouped.items()
        if len({member.bssid for member in members}) > 1
    }


def detect_channel_congestion(networks: List[WifiNetwork], threshold: int = 3) -> Dict[str, int]:
    """
    Return channels with network counts at or above the congestion threshold.
    """
    channel_counts: Dict[str, int] = {}

    for net in networks:
        channel = net.channel.strip() or "Unknown"
        channel_counts[channel] = channel_counts.get(channel, 0) + 1

    return {
        channel: count
        for channel, count in channel_counts.items()
        if channel != "Unknown" and count >= threshold
    }


def apply_environment_detections(networks: List[WifiNetwork]) -> None:
    """
    Apply higher-level environment detections:
    - duplicate SSID / possible evil twin candidate
    - congested channels
    """
    duplicate_ssids = detect_duplicate_ssids(networks)
    congested_channels = detect_channel_congestion(networks)

    # Duplicate SSID / possible evil twin detection
    for ssid, members in duplicate_ssids.items():
        for member in members:
            warning = (
                f"Duplicate SSID detected ({len(members)} BSSIDs) - "
                f"possible multi-AP deployment or evil twin candidate"
            )
            if warning not in member.warnings:
                member.warnings.append(warning)

            # Slightly reduce score because duplication can be suspicious
            member.score = max(0, member.score - 8)

            if member.score >= 85:
                member.assessment = "Highly Secure"
            elif member.score >= 70:
                member.assessment = "Moderately Secure"
            elif member.score >= 45:
                member.assessment = "Needs Attention"
            else:
                member.assessment = "High Risk"

    # Channel congestion detection
    for net in networks:
        channel = net.channel.strip() or "Unknown"
        if channel in congested_channels:
            warning = (
                f"Channel {channel} is congested "
                f"({congested_channels[channel]} networks detected)"
            )
            if warning not in net.warnings:
                net.warnings.append(warning)

            # Small penalty for congestion
            net.score = max(0, net.score - 5)

            if net.score >= 85:
                net.assessment = "Highly Secure"
            elif net.score >= 70:
                net.assessment = "Moderately Secure"
            elif net.score >= 45:
                net.assessment = "Needs Attention"
            else:
                net.assessment = "High Risk"


def display_summary(networks: List[WifiNetwork]) -> None:
    """
    Display an environment-wide security summary.
    """
    if not networks:
        return

    total = len(networks)
    highly_secure = sum(1 for net in networks if net.assessment == "Highly Secure")
    moderately_secure = sum(1 for net in networks if net.assessment == "Moderately Secure")
    needs_attention = sum(1 for net in networks if net.assessment == "Needs Attention")
    high_risk = sum(1 for net in networks if net.assessment == "High Risk")

    duplicate_ssids = detect_duplicate_ssids(networks)
    congested_channels = detect_channel_congestion(networks)

    if high_risk > 0:
        env_risk = "HIGH"
        env_color = Fore.RED
    elif needs_attention > 0:
        env_risk = "MEDIUM"
        env_color = Fore.YELLOW
    else:
        env_risk = "LOW"
        env_color = Fore.GREEN

    print()
    print(Fore.CYAN + "=" * 55)
    print(Fore.CYAN + "                 FINAL ENVIRONMENT SUMMARY")
    print(Fore.CYAN + "=" * 55)
    print(Fore.WHITE + f"Total Networks         : {total}")
    print(Fore.GREEN + f"Highly Secure          : {highly_secure}")
    print(Fore.YELLOW + f"Moderately Secure      : {moderately_secure}")
    print(Fore.MAGENTA + f"Needs Attention        : {needs_attention}")
    print(Fore.RED + f"High Risk              : {high_risk}")
    print(env_color + f"Overall Environment Risk: {env_risk}")

    if duplicate_ssids:
        print(Fore.MAGENTA + "\nPossible Duplicate SSIDs:")
        for ssid, members in duplicate_ssids.items():
            print(Fore.MAGENTA + f"  - {ssid} ({len(members)} BSSIDs)")
    else:
        print(Fore.GREEN + "\nPossible Duplicate SSIDs: None")

    if congested_channels:
        print(Fore.MAGENTA + "\nCongested Channels:")
        for channel, count in sorted(congested_channels.items(), key=lambda item: item[0]):
            print(Fore.MAGENTA + f"  - Channel {channel}: {count} networks")
    else:
        print(Fore.GREEN + "\nCongested Channels: None")

    print(Fore.CYAN + "=" * 55)

def export_to_csv(networks: List[WifiNetwork], filename: str = "outputs/scan_results.csv") -> None:
    import csv

    try:
        with open(filename, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)

            writer.writerow([
                "SSID",
                "BSSID",
                "Signal",
                "Channel",
                "Security",
                "Score",
                "Assessment",
                "Warnings"
            ])

            for net in networks:
                writer.writerow([
                    net.ssid,
                    net.bssid,
                    net.signal,
                    net.channel,
                    net.security,
                    net.score,
                    net.assessment,
                    "; ".join(net.warnings)
                ])

        print(Fore.GREEN + f"\n[+] Results exported to {filename}")

    except Exception as e:
        print(Fore.RED + f"[!] Failed to export results: {e}")

def display_networks(networks: List[WifiNetwork]) -> None:
    if not networks:
        print(Fore.YELLOW + "[!] No WiFi networks detected.")
        return

    print(Fore.GREEN + f"[+] Found {len(networks)} network(s)\n")

    for index, net in enumerate(networks, start=1):
        print(Fore.YELLOW + "-" * 55)
        print(Fore.CYAN + f"[{index}] {net.ssid}")
        print(Fore.WHITE + f"  BSSID       : {net.bssid}")
        print(Fore.WHITE + f"  Signal      : {net.signal}%  {signal_bar(net.signal)}")
        print(Fore.WHITE + f"  Channel     : {net.channel}")
        print(Fore.WHITE + f"  Security    : {net.security}")

        # Color-coded assessment
        assessment_color = Fore.GREEN
        if net.assessment == "Moderately Secure":
            assessment_color = Fore.YELLOW
        elif net.assessment in ("Needs Attention", "High Risk"):
            assessment_color = Fore.RED

        print(Fore.WHITE + f"  Score       : {net.score}/100")
        print(assessment_color + f"  Assessment  : {net.assessment}")

        if net.warnings:
            print(Fore.MAGENTA + "  Warnings    :")
            for warning in net.warnings:
                print(Fore.MAGENTA + f"    - {warning}")
        else:
            print(Fore.GREEN + "  Warnings    : None")

    print(Fore.YELLOW + "-" * 55)


def main() -> None:
    print_banner()

    try:
        networks = get_networks()

        analyze_networks(networks)
        apply_environment_detections(networks)

        print(Fore.GREEN + "[+] Scan completed successfully.\n")
        display_networks(networks)
        display_summary(networks)

        export_to_csv(networks)

    except RuntimeError as err:
        print(Fore.RED + f"[!] Error: {err}")
        sys.exit(1)
    except Exception as err:
        print(Fore.RED + f"[!] Unexpected error: {err}")
        sys.exit(1)
        
if __name__ == "__main__":
    main()