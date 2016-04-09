package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

const (
	Interface = "en0"
)

type Host struct {
	IP       string
	MAC      string
	Hostname string
	Data     []string
}

func (h Host) String() string {
	return fmt.Sprintf("Host %s has IP %s, MAC: %s", h.Hostname, h.IP, h.MAC)
}

func handleErr(err error) {
	log.Println("Error: ", err)
}

func getIPAndMAC(line string) (string, string) {
	lines := strings.Split(line, "(")
	tmp := strings.Split(lines[1], ")")
	IP := tmp[0]
	MAC := strings.Split(tmp[1], " ")[2]
	return IP, MAC
}

func arpEntries() []Host {
	var hosts []Host
	out, err := exec.Command("arp", "-na").Output()
	if err != nil {
		handleErr(err)
	}
	strOut := string(out)
	lines := strings.Split(strOut, "\n")
	for _, line := range lines {
		if strings.Contains(line, Interface) {
			h := Host{}
			h.IP, h.MAC = getIPAndMAC(line)
			hosts = append(hosts, h)
		}
	}
	return hosts
}

func display(hs []Host) {
	for idx, h := range hs {
		log.Printf("%d. %s", idx+1, h)
	}
	return
}

func myLANIP() (string, error) {
	ifis, err := net.Interfaces()
	if err != nil {
		handleErr(err)
	}
	for _, ifi := range ifis {
		if ifi.Name == Interface {
			addrs, err := ifi.Addrs()
			if err != nil {
				handleErr(err)
			}
			log.Println(addrs)
			for _, addr := range addrs {
				ip, _, err := net.ParseCIDR(addr.String())
				if err != nil {
					handleErr(err)
					continue
				}
				if ip.To4() != nil {
					return addr.String(), nil
				}
			}
		}
	}
	return "", err
}

func nmapEntries() {
	myIP, err := myLANIP()
	handleErr(err)
	out, err := exec.Command("nmap", "-sP", myIP).Output()
	handleErr(err)
	log.Println(string(out))
}

func main() {
	hosts := arpEntries()
	display(hosts)
	nmapEntries()
}
