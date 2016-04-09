package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"time"
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

func nmapScanAll() {
	myIP, err := myLANIP()
	handleErr(err)
	out, err := exec.Command("nmap", "-A", "-T4", myIP).Output()
	handleErr(err)
	log.Println(string(out))
}
func nmapEntries() {
	myIP, err := myLANIP()
	handleErr(err)
	out, err := exec.Command("nmap", "-sP", "-PA21,22,25,3389", myIP).Output()
	handleErr(err)
	log.Println(string(out))
}

type Event struct {
	When time.Time
	Up   bool
}

func (e Event) String() string {
	var s string
	if e.Up {
		s = "UP"
	} else {
		s = "DOWN"
	}

	return fmt.Sprintf("Event %s at %s", s, e.When)
}
func checkPing(h Host) Event {
	out, err := exec.Command("nmap", "-sP", h.IP).Output()
	if err == nil {
		if strings.Contains(string(out), "1 host up") {
			return Event{time.Now(), true}
		}
	}
	return Event{time.Now(), false}
}

func checkAll(hosts []Host, ch chan Event, chost chan Host) {
	for _, host := range hosts {
		ch <- checkPing(host)
		chost <- host
	}
	close(ch)
	close(chost)
}

func main() {
	hosts := arpEntries()
	ch := make(chan Event)
	chost := make(chan Host)
	go checkAll(hosts, ch, chost)
	for i := range ch {
		log.Println(<-chost, i)
	}

	// TODO add nmap entries to ping check
	nmapEntries()

	// For every 5 mins, run a check and save result to db.
	// Loop over all host in buckets and all host that nmap can ping
	// If a host change its state (leaving), save data to db and report.
	// If host is new, add it
	// If host does not change, do nothing
	nmapScanAll()
}
