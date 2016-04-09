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
	monInterface = "en0"
	statusUp     = "UP"
	statusDown   = "DOWN"
)

// Host capture a host info in net
type Host struct {
	IP       string
	MAC      string
	Hostname string
	Pings    []Event
}

func (h Host) String() string {
	return fmt.Sprintf("Host %s has IP %s, MAC: %s", h.Hostname, h.IP, h.MAC)
}

func (h *Host) checkPing() error {
	e := Event{When: time.Now()}
	out, err := exec.Command("nmap", "-sP", h.IP).Output()
	if err != nil {
		return err
	}
	if strings.Contains(string(out), "1 host up") {
		e.Up = true
	}
	h.Pings = append(h.Pings, e)
	log.Println(h.Pings)
	return nil
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
		if strings.Contains(line, monInterface) {
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
		if ifi.Name == monInterface {
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

// Event capture
type Event struct {
	When time.Time
	Up   bool
}

func (e Event) String() string {
	var s string
	if e.Up {
		s = statusUp
	} else {
		s = statusDown
	}

	return fmt.Sprintf("Event %s at %s", s, e.When)
}

func checkAll(hosts []Host) {
	errChan := make(chan error)
	for _, host := range hosts {
		go func() {
			errChan <- host.checkPing()
		}()
	}
	close(errChan)

	for e := range errChan {
		handleErr(e)
	}
}

func main() {
	hosts := arpEntries()
	checkAll(hosts)
	// TODO add nmap entries to ping check
	nmapEntries()

	// For every 5 mins, run a check and save result to db.
	// Loop over all host in buckets and all host that nmap can ping
	// If a host change its state (leaving), save data to db and report.
	// If host is new, add it
	// If host does not change, do nothing
	nmapScanAll()
}
