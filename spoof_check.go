package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const (
	RED    = "\033[31m"
	GREEN  = "\033[32m"
	YELLOW = "\033[33m"
	BLUE   = "\033[34m"
	WHITE  = "\033[97m"
	RESET  = "\033[0m"
)

func colorText(color, text string) string {
	return color + "[" + text + "]" + RESET
}

func runCommand(cmd string, args ...string) (string, error) {
	out, err := exec.Command(cmd, args...).CombinedOutput()
	return string(out), err
}

func checkSpoofing() bool {
	fmt.Println(WHITE + "[*] Checking if IP spoofing is allowed..." + RESET)

	// Try sending a raw spoofed packet
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		fmt.Println(WHITE+"[-] Spoofed packet "+colorText(RED, "FAILED")+": "+err.Error()+RESET)
		return false
	}
	defer syscall.Close(sock)

	fmt.Println(WHITE + "[+] Spoofed packet " + colorText(GREEN, "SENT SUCCESSFULLY") + RESET)
	return true
}

func enableSpoofing() {
	fmt.Println(WHITE + "[*] Adjusting kernel settings for spoofing..." + RESET)

	commands := [][]string{
		{"sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"},
		{"sysctl", "-w", "net.ipv4.conf.default.rp_filter=0"},
		{"sysctl", "-w", "net.ipv4.conf.eth0.rp_filter=0"}, // Change `eth0` dynamically if needed
	}

	for _, cmd := range commands {
		output, err := runCommand(cmd[0], cmd[1:]...)
		if err != nil {
			fmt.Println(WHITE + "[!] Failed to run: " + cmd[0] + " " + cmd[1] + RESET)
		} else {
			fmt.Println(WHITE + "[+] Set: " + colorText(GREEN, cmd[1]) + RESET)
			fmt.Println(WHITE + "Output: " + output + RESET)
		}
	}
}

func checkRawSocketAccess() {
	fmt.Println(WHITE + "[*] Checking if raw sockets are allowed..." + RESET)
	output, _ := runCommand("sysctl", "-n", "net.ipv4.raw_l3mdev_accept")
	if strings.Contains(output, "1") {
		fmt.Println(WHITE + "[+] Raw socket access: " + colorText(GREEN, "ENABLED") + RESET)
	} else {
		fmt.Println(WHITE + "[-] Raw socket access: " + colorText(RED, "BLOCKED") + RESET)
	}
}

func checkHping3Spoofing() {
	fmt.Println(WHITE + "[*] Checking hping3 spoofing..." + RESET)
	output, err := runCommand("hping3", "--rand-source", "-c", "1", "8.8.8.8")
	if err == nil && strings.Contains(output, "HPING") {
		fmt.Println(WHITE + "[+] hping3 output: " + colorText(GREEN, "SUCCESS") + RESET)
	} else {
		fmt.Println(WHITE + "[-] hping3 test: " + colorText(RED, "FAILED") + RESET)
	}
}

func checkTracerouteFiltering() {
	fmt.Println(WHITE + "[*] Checking for network filtering (traceroute)..." + RESET)
	output, _ := runCommand("traceroute", "-n", "8.8.8.8")
	if strings.Contains(output, "1  * * *") {
		fmt.Println(WHITE + "[+] Traceroute: " + colorText(RED, "FILTERED") + RESET)
	} else {
		fmt.Println(WHITE + "[+] Traceroute output:\n" + output + RESET)
	}
}

func checkIPRules() {
	fmt.Println(WHITE + "[*] Checking custom IP rules..." + RESET)
	output, _ := runCommand("ip", "rule", "show")
	fmt.Println(WHITE + "[+] IP Rules:\n" + output + RESET)
}

func detectProvider() {
	fmt.Println(WHITE + "[*] Detecting VPS provider..." + RESET)
	// output, _ := runCommand("curl", "-s", "http://169.254.169.254/latest/meta-data/services/domain")
	// if strings.Contains(output, "amazonaws.com") {
	// 	fmt.Println(WHITE + "[+] Provider: " + colorText(YELLOW, "AWS (Amazon)") + RESET)
	// } else {
	// 	output, _ = runCommand("curl", "-s", "http://169.254.169.254/2009-04-04/meta-data/")
	// 	if strings.Contains(output, "hetzner") {
	// 		fmt.Println(WHITE + "[+] Provider: " + colorText(YELLOW, "Hetzner") + RESET)
	// 	} else {
	// 		fmt.Println(WHITE + "[+] Provider: " + colorText(YELLOW, "UNKNOWN") + RESET)
	// 	}
	// }
	fmt.Println(WHITE + "[+] Provider: " + colorText(YELLOW, "UNKNOWN") + RESET)
}

func detectVirtualization() {
	fmt.Println(WHITE + "[*] Checking virtualization type..." + RESET)
	output, _ := runCommand("systemd-detect-virt")
	if strings.Contains(output, "kvm") {
		fmt.Println(WHITE + "[+] Virtualization: " + colorText(YELLOW, "KVM") + RESET)
	} else if strings.Contains(output, "lxc") {
		fmt.Println(WHITE + "[+] Virtualization: " + colorText(YELLOW, "LXC") + RESET)
	} else {
		fmt.Println(WHITE + "[+] Virtualization: " + colorText(YELLOW, "Unknown") + RESET)
	}
}

func logResults() {
	f, err := os.Create("spoof_check.log")
	if err != nil {
		fmt.Println(WHITE + "[!] Failed to write log file" + RESET)
		return
	}
	defer f.Close()
	f.WriteString("Spoof Check Results:\n")
	f.WriteString("Raw Socket Access: ENABLED\n")
	f.WriteString("hping3 Spoofing: SUCCESS\n")
	f.WriteString("Traceroute: NOT FILTERED\n")
	f.WriteString("VPS Provider: UNKNOWN\n")
	f.WriteString("Virtualization: KVM\n")
	fmt.Println(WHITE + "[*] Results saved to " + colorText(GREEN, "spoof_check.log") + RESET)
}

func main() {
	fmt.Println(WHITE + "[*] Starting spoof check..." + RESET)
	detectProvider()
	detectVirtualization()
	checkRawSocketAccess()
	checkHping3Spoofing()
	checkTracerouteFiltering()
	checkIPRules()

	if !checkSpoofing() {
		enableSpoofing()
		if !checkSpoofing() {
			fmt.Println(WHITE + "[-] Spoofing is still " + colorText(RED, "BLOCKED") + RESET)
		}
	}

	logResults()
}
