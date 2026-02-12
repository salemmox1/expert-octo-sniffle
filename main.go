package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	R  = "\033[31m"
	G  = "\033[32m"
	Y  = "\033[33m"
	CY = "\033[36m"
	W  = "\033[37m"
	RE = "\033[0m"
)

type Counter struct {
	sync.Mutex
	Processed int
	NLA       int
	NonNLA    int
	Error     int
	Timeout   int
}

// زيادة الآي بي للبث المباشر
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 { break }
	}
}

// بث النطاقات لتوفير الرام
func streamCIDR(cidr string, jobs chan<- string) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		jobs <- cidr
		return
	}
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		currentIP := ip.String()
		if strings.HasSuffix(currentIP, ".0") || strings.HasSuffix(currentIP, ".255") { continue }
		jobs <- currentIP
	}
}

func manageBackups() {
	files := []string{"nla.txt", "nonla.txt", "error.txt", "timeout.txt"}
	needsBackup := false
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			needsBackup = true
			break
		}
	}
	if needsBackup {
		index := 0
		var folderName string
		for {
			folderName = fmt.Sprintf("nla_backup_%d", index)
			if _, err := os.Stat(folderName); os.IsNotExist(err) { break }
			index++
		}
		os.Mkdir(folderName, 0755)
		for _, f := range files {
			if _, err := os.Stat(f); err == nil { os.Rename(f, filepath.Join(folderName, f)) }
		}
		fmt.Printf("%s[*] Backup created: %s%s\n", Y, folderName, RE)
	}
}

// الفحص الاحترافي المعتمد على منطق grdp
func checkRDPDeep(ip string, port int, timeout time.Duration) (string, bool) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() { return "TIMEOUT", false }
		return "ERROR", false
	}
	defer conn.Close()

	// حزمة Negotiation Request (تطلب CredSSP, RDP, SSL)
	// مأخوذة من معايير [MS-RDPBCGR]
	pkt := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT (Header)
		0x0e,                   // X.224 (Length)
		0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, // X.224 (Connection Request)
		0x00, 0x08, 0x00,       // RDP NegData (Type & Length)
		0x03, 0x00, 0x00, 0x00, // Flags: نطلب (RDP + SSL + NLA/CredSSP)
	}

	conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write(pkt)
	if err != nil { return "ERROR", false }

	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil { return "ERROR", false }

	// 1. التحقق من هوية السيرفر (TPKT & X.224)
	if n < 11 || resp[0] != 0x03 || resp[5] != 0xd0 {
		return "ERROR", false // ليس سيرفر RDP حقيقي أو بورت مخادع
	}

	// 2. فحص الـ RDP Negotiation Response
	// السيرفر يرد بـ Protocol Selection في البايت رقم 15
	// 0x02 = SSL (تدعم NLA عادة)
	// 0x00 = Standard RDP (لا تدعم NLA - Vuln)
	
	// منطق grdp للـ NLA:
	// إذا كان السيرفر يدعم بروتوكول 0 (Standard RDP Security) فهذا يعني غالباً Non-NLA
	// وإذا رد بـ RDP_NEG_RSP وطول البيانات يشير لعدم وجود بروتوكولات حماية متطورة.
	
	protocolSelected := resp[n-4] 

	if protocolSelected == 0x00 {
		return "NONLA", true
	}

	// إذا كانت الاستجابة قصيرة جداً (11 بايت) فهي غالباً أنظمة قديمة مكشوفة
	if n == 11 {
		return "NONLA", true
	}

	return "NLA", false
}

func main() {
	fmt.Print("\033[H\033[2J")
	fmt.Printf("%s#################################################\n", CY)
	fmt.Printf("#    RDP INTEL MASTER - DEEP SCAN v8.0          #\n")
	fmt.Printf("#################################################%s\n\n", RE)

	manageBackups()

	var fileName string
	fmt.Printf("%s[?] Enter IP file name [IP.txt]: %s", Y, W)
	fmt.Scanln(&fileName)
	if fileName == "" { fileName = "IP.txt" }

	fmt.Printf("%s[?] Port [3389]: %s", Y, W)
	pStr := "3389"; fmt.Scanln(&pStr)
	port, _ := strconv.Atoi(pStr)

	fmt.Printf("%s[?] Threads [500]: %s", Y, W)
	tStr := "500"; fmt.Scanln(&tStr)
	threads, _ := strconv.Atoi(tStr)
	if threads <= 0 { threads = 500 }

	fmt.Printf("%s[?] Timeout (Sec) [5]: %s", Y, W)
	toStr := "5"; fmt.Scanln(&toStr)
	toSec, _ := strconv.Atoi(toStr)
	if toSec <= 0 { toSec = 5 }
	timeout := time.Duration(toSec) * time.Second

	count := &Counter{}
	jobs := make(chan string, threads*2)
	var wg sync.WaitGroup

	fNla, _ := os.OpenFile("nla.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	fNonla, _ := os.OpenFile("nonla.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	fErr, _ := os.OpenFile("error.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	fTime, _ := os.OpenFile("timeout.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				status, _ := checkRDPDeep(ip, port, timeout)
				count.Lock()
				count.Processed++
				switch status {
				case "NONLA":
					count.NonNLA++
					fmt.Printf("\r\033[K%s[VULN] %s:%d%s\n", R, ip, port, RE)
					fNonla.WriteString(ip + "\n")
				case "NLA":
					count.NLA++
					fNla.WriteString(ip + "\n")
				case "TIMEOUT":
					count.Timeout++
					fTime.WriteString(ip + "\n")
				case "ERROR":
					count.Error++
					fErr.WriteString(ip + "\n")
				}
				fmt.Printf("\r%s[Processed: %d] %sNLA:%d %sNON-NLA:%d %sTO:%d %sERR:%d%s", 
					W, count.Processed, G, count.NLA, R, count.NonNLA, Y, count.Timeout, CY, count.Error, RE)
				count.Unlock()
			}
		}()
	}

	go func() {
		file, err := os.Open(fileName)
		if err != nil { close(jobs); return }
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" { continue }
			if strings.Contains(line, "/") {
				streamCIDR(line, jobs)
			} else {
				jobs <- line
			}
		}
		file.Close()
		close(jobs)
	}()

	wg.Wait()
	fmt.Printf("\n\n%s[+] Deep Scan Complete!%s\n", G, RE)
}