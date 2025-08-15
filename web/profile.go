package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xxf098/lite-proxy/config"
	"github.com/xxf098/lite-proxy/download"
	"github.com/xxf098/lite-proxy/request"
	"github.com/xxf098/lite-proxy/utils"
	"github.com/xxf098/lite-proxy/web/render"
	"gopkg.in/yaml.v3"
)

var (
	ErrInvalidData = errors.New("invalid data")
	regProfile     = regexp.MustCompile(`((?i)vmess://(\S+?)@(\S+?):([0-9]{2,5})/([?#][^\s]+))|((?i)vmess://[a-zA-Z0-9+_/=-]+([?#][^\s]+)?)|((?i)ssr://[a-zA-Z0-9+_/=-]+)|((?i)(vless|ss|trojan)://(\S+?)@(\S+?):([0-9]{2,5})/?([?#][^\s]+))|((?i)(ss)://[a-zA-Z0-9+_/=-]+([?#][^\s]+))`)
)

const (
	PIC_BASE64 = iota
	PIC_PATH
	PIC_NONE
	JSON_OUTPUT
	TEXT_OUTPUT
	YAML_OUTPUT
)

type PAESE_TYPE int

const (
	PARSE_ANY PAESE_TYPE = iota
	PARSE_URL
	PARSE_FILE
	PARSE_BASE64
	PARSE_CLASH
	PARSE_PROFILE
)

// support proxy
// concurrency setting
// as subscription server
// profiles filter
// clash to vmess local subscription
func getSubscriptionLinks(link string) ([]string, error) {
	c := http.Client{
		Timeout: 20 * time.Second,
	}
	resp, err := c.Get(link)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if isYamlFile(link) {
		return scanClashProxies(resp.Body, true)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	dataStr := string(data)
	msg, err := utils.DecodeB64(dataStr)
	if err != nil {
		if strings.Contains(dataStr, "proxies:") {
			return parseClash(dataStr)
		} else if strings.Contains(dataStr, "vmess://") ||
			strings.Contains(dataStr, "trojan://") ||
			strings.Contains(dataStr, "ssr://") ||
			strings.Contains(dataStr, "ss://") {
			return parseProfiles(dataStr)
		} else {
			return []string{}, err
		}
	}
	return ParseLinks(msg)
}

type parseFunc func(string) ([]string, error)

type ParseOption struct {
	Type PAESE_TYPE
}

// api
func ParseLinks(message string) ([]string, error) {
	opt := ParseOption{Type: PARSE_ANY}
	return ParseLinksWithOption(message, opt)
}

// api
func ParseLinksWithOption(message string, opt ParseOption) ([]string, error) {
	// matched, err := regexp.MatchString(`^(?:https?:\/\/)(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)`, message)
	if opt.Type == PARSE_URL || utils.IsUrl(message) {
		log.Println(message)
		return getSubscriptionLinks(message)
	}
	// check is file path
	if opt.Type == PARSE_FILE || utils.IsFilePath(message) {
		return parseFile(message)
	}
	if opt.Type == PARSE_BASE64 {
		return parseBase64(message)
	}
	if opt.Type == PARSE_CLASH {
		return parseClash(message)
	}
	if opt.Type == PARSE_PROFILE {
		return parseProfiles(message)
	}
	var links []string
	var err error
	for _, fn := range []parseFunc{parseProfiles, parseBase64, parseClash, parseFile} {
		links, err = fn(message)
		if err == nil && len(links) > 0 {
			break
		}
	}
	return links, err
}

func parseProfiles(data string) ([]string, error) {
	// encodeed url
	links := strings.Split(data, "\n")
	if len(links) > 1 {
		for i, link := range links {
			if l, err := url.Parse(link); err == nil {
				if query, err := url.QueryUnescape(l.RawQuery); err == nil && query == l.RawQuery {
					links[i] = l.String()
				}
			}
		}
		data = strings.Join(links, "\n")
	}
	// reg := regexp.MustCompile(`((?i)vmess://(\S+?)@(\S+?):([0-9]{2,5})/([?#][^\s]+))|((?i)vmess://[a-zA-Z0-9+_/=-]+([?#][^\s]+)?)|((?i)ssr://[a-zA-Z0-9+_/=-]+)|((?i)(vless|ss|trojan)://(\S+?)@(\S+?):([0-9]{2,5})([?#][^\s]+))|((?i)(ss)://[a-zA-Z0-9+_/=-]+([?#][^\s]+))`)
	matches := regProfile.FindAllStringSubmatch(data, -1)
	linksLen, matchesLen := len(links), len(matches)
	if linksLen < matchesLen {
		links = make([]string, matchesLen)
	} else if linksLen > matchesLen {
		links = links[:len(matches)]
	}
	for index, match := range matches {
		link := match[0]
		if config.RegShadowrocketVmess.MatchString(link) {
			if l, err := config.ShadowrocketLinkToVmessLink(link); err == nil {
				link = l
			}
		}
		links[index] = link
	}
	return links, nil
}

func parseBase64(data string) ([]string, error) {
	msg, err := utils.DecodeB64(data)
	if err != nil {
		return nil, err
	}
	return parseProfiles(msg)
}

func parseClash(data string) ([]string, error) {
	cc, err := config.ParseClash(utils.UnsafeGetBytes(data))
	if err != nil {
		return parseClashProxies(data)
	}
	return cc.Proxies, nil
}

// split to new line
func parseClashProxies(input string) ([]string, error) {

	if !strings.Contains(input, "{") {
		return []string{}, nil
	}
	return scanClashProxies(strings.NewReader(input), true)
}

func scanClashProxies(r io.Reader, greedy bool) ([]string, error) {
	proxiesStart := false
	var data []byte
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		b := scanner.Bytes()
		trimLine := strings.TrimSpace(string(b))
		if trimLine == "proxy-groups:" || trimLine == "rules:" || trimLine == "Proxy Group:" {
			break
		}
		if !proxiesStart && (trimLine == "proxies:" || trimLine == "Proxy:") {
			proxiesStart = true
			b = []byte("proxies:")
		}
		if proxiesStart {
			if _, err := config.ParseBaseProxy(trimLine); err != nil {
				continue
			}
			data = append(data, b...)
			data = append(data, byte('\n'))
		}
	}
	// fmt.Println(string(data))
	return parseClashByte(data)
}

func parseClashFileByLine(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return scanClashProxies(file, false)
}

func parseClashByte(data []byte) ([]string, error) {
	cc, err := config.ParseClash(data)
	if err != nil {
		return nil, err
	}
	return cc.Proxies, nil
}

func parseFile(filepath string) ([]string, error) {
	filepath = strings.TrimSpace(filepath)
	if _, err := os.Stat(filepath); err != nil {
		return nil, err
	}
	// clash
	if isYamlFile(filepath) {
		return parseClashFileByLine(filepath)
	}
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	links, err := parseBase64(string(data))
	if err != nil && len(data) > 2048 {
		preview := string(data[:2048])
		if strings.Contains(preview, "proxies:") {
			return scanClashProxies(bytes.NewReader(data), true)
		}
		if strings.Contains(preview, "vmess://") ||
			strings.Contains(preview, "trojan://") ||
			strings.Contains(preview, "ssr://") ||
			strings.Contains(preview, "ss://") {
			return parseProfiles(string(data))
		}
	}
	return links, err
}

func parseOptions(message string) (*ProfileTestOptions, error) {
	opts := strings.Split(message, "^")
	if len(opts) < 7 {
		return nil, ErrInvalidData
	}
	groupName := opts[0]
	if groupName == "?empty?" || groupName == "" {
		groupName = "Default"
	}
	concurrency, err := strconv.Atoi(opts[5])
	if err != nil {
		return nil, err
	}
	if concurrency < 1 {
		concurrency = 1
	}
	timeout, err := strconv.Atoi(opts[6])
	if err != nil {
		return nil, err
	}
	if timeout < 20 {
		timeout = 20
	}
	testOpt := &ProfileTestOptions{
		GroupName:     groupName,
		SpeedTestMode: opts[1],
		PingMethod:    opts[2],
		SortMethod:    opts[3],
		Concurrency:   concurrency,
		TestMode:      ALLTEST,
		Timeout:       time.Duration(timeout) * time.Second,
	}
	return testOpt, nil
}

const (
	SpeedOnly = "speedonly"
	PingOnly  = "pingonly"
	ALLTEST   = iota
	RETEST
)

type ProfileTestOptions struct {
	GroupName       string        `json:"group"`
	SpeedTestMode   string        `json:"speedtestMode"` // speedonly pingonly all
	PingMethod      string        `json:"pingMethod"`    // googleping
	SortMethod      string        `json:"sortMethod"`    // speed rspeed ping rping
	Concurrency     int           `json:"concurrency"`
	TestMode        int           `json:"testMode"` // 2: ALLTEST 3: RETEST
	TestIDs         []int         `json:"testids"`
	Timeout         time.Duration `json:"timeout"`
	Links           []string      `json:"links"`
	Subscription    string        `json:"subscription"`
	Language        string        `json:"language"`
	FontSize        int           `json:"fontSize"`
	Theme           string        `json:"theme"`
	Unique          bool          `json:"unique"`
	GeneratePicMode int           `json:"generatePicMode"` // 0: base64 1:pic path 2: no pic 3: json @deprecated use outputMode
	OutputMode      int           `json:"outputMode"`
}

type JSONOutput struct {
	Nodes        []render.Node      `json:"nodes"`
	Options      ProfileTestOptions `json:"options"`
	Traffic      int64              `json:"traffic"`
	Duration     string             `json:"duration"`
	SuccessCount int                `json:"successCount"`
	LinksCount   int                `json:"linksCount"`
}

func parseMessage(message []byte) ([]string, *ProfileTestOptions, error) {
	options := &ProfileTestOptions{}
	err := json.Unmarshal(message, options)
	if err != nil {
		return nil, nil, err
	}
	options.Timeout = time.Duration(int(options.Timeout)) * time.Second
	if options.GroupName == "?empty?" || options.GroupName == "" {
		options.GroupName = "Default"
	}
	if options.Timeout < 8 {
		options.Timeout = 8
	}
	if options.Concurrency < 1 {
		options.Concurrency = 1
	}
	if options.TestMode == RETEST {
		return options.Links, options, nil
	}
	options.TestMode = ALLTEST
	links, err := ParseLinks(options.Subscription)
	if err != nil {
		return nil, nil, err
	}
	return links, options, nil
}

func parseRetestMessage(message []byte) ([]string, *ProfileTestOptions, error) {
	options := &ProfileTestOptions{}
	err := json.Unmarshal(message, options)
	if err != nil {
		return nil, nil, err
	}
	if options.TestMode != RETEST {
		return nil, nil, errors.New("not retest mode")
	}
	options.TestMode = RETEST
	options.Timeout = time.Duration(int(options.Timeout)) * time.Second
	if options.GroupName == "?empty?" || options.GroupName == "" {
		options.GroupName = "Default"
	}
	if options.Timeout < 20 {
		options.Timeout = 20
	}
	if options.Concurrency < 1 {
		options.Concurrency = 1
	}
	return options.Links, options, nil
}

type MessageWriter interface {
	WriteMessage(messageType int, data []byte) error
}

type OutputMessageWriter struct {
}

func (p *OutputMessageWriter) WriteMessage(messageType int, data []byte) error {
	log.Println(string(data))
	return nil
}

type EmptyMessageWriter struct {
}

func (w *EmptyMessageWriter) WriteMessage(messageType int, data []byte) error {
	return nil
}

type ProfileTest struct {
	Writer      MessageWriter
	Options     *ProfileTestOptions
	MessageType int
	Links       []string
	mu          sync.Mutex
	wg          sync.WaitGroup // wait for all to finish
}

func (p *ProfileTest) WriteMessage(data []byte) error {
	var err error
	if p.Writer != nil {
		p.mu.Lock()
		err = p.Writer.WriteMessage(p.MessageType, data)
		p.mu.Unlock()
	}
	return err
}

func (p *ProfileTest) WriteString(data string) error {
	b := []byte(data)
	return p.WriteMessage(b)
}

// api
// render.Node contain the final test result
func (p *ProfileTest) TestAll(ctx context.Context, trafficChan chan<- int64) (chan render.Node, error) {
	links := p.Links
	linksCount := len(links)
	if linksCount < 1 {
		return nil, fmt.Errorf("profile not found")
	}
	nodeChan := make(chan render.Node, linksCount)
	go func(context.Context) {
		guard := make(chan int, p.Options.Concurrency)
		for i := range links {
			p.wg.Add(1)
			id := i
			link := links[i]
			select {
			case guard <- i:
				go func(id int, link string, c <-chan int, nodeChan chan<- render.Node) {
					p.testOne(ctx, id, link, nodeChan, trafficChan)
					<-c
				}(id, link, guard, nodeChan)
			case <-ctx.Done():
				return
			}
		}
		// p.wg.Wait()
		// if trafficChan != nil {
		// 	close(trafficChan)
		// }
	}(ctx)
	return nodeChan, nil
}

func (p *ProfileTest) testAll(ctx context.Context) (render.Nodes, error) {
	linksCount := len(p.Links)
	if linksCount < 1 {
		p.WriteString(SPEEDTEST_ERROR_NONODES)
		return nil, fmt.Errorf("no profile found")
	}
	start := time.Now()
	p.WriteMessage(getMsgByte(-1, "started"))
	// for i := range p.Links {
	// 	p.WriteMessage(gotserverMsg(i, p.Links[i], p.Options.GroupName))
	// }
	step := 9
	if linksCount > 200 {
		step = linksCount / 20
		if step > 50 {
			step = 50
		}
	}
	for i := 0; i < linksCount; {
		end := i + step
		if end > linksCount {
			end = linksCount
		}
		links := p.Links[i:end]
		msg := gotserversMsg(i, links, p.Options.GroupName)
		p.WriteMessage(msg)
		i += step
	}
	guard := make(chan int, p.Options.Concurrency)
	nodeChan := make(chan render.Node, linksCount)

	nodes := make(render.Nodes, linksCount)
	for i := range p.Links {
		p.wg.Add(1)
		id := i
		link := ""
		if len(p.Options.TestIDs) > 0 && len(p.Options.Links) > 0 {
			id = p.Options.TestIDs[i]
			link = p.Options.Links[i]
		}
		select {
		case guard <- i:
			go func(id int, link string, c <-chan int, nodeChan chan<- render.Node) {
				p.testOne(ctx, id, link, nodeChan, nil)
				_ = p.WriteMessage(getMsgByte(id, "endone"))
				<-c
			}(id, link, guard, nodeChan)
		case <-ctx.Done():
			return nil, nil
		}
	}
	p.wg.Wait()
	p.WriteMessage(getMsgByte(-1, "eof"))
	duration := FormatDuration(time.Since(start))
	// draw png
	successCount := 0
	var traffic int64 = 0
	for i := 0; i < linksCount; i++ {
		node := <-nodeChan
		node.Link = p.Links[node.Id]
		nodes[node.Id] = node
		traffic += node.Traffic
		if node.IsOk {
			successCount += 1
		}
	}
	close(nodeChan)

	if p.Options.OutputMode == PIC_NONE {
		return nodes, nil
	}

	// sort nodes
	nodes.Sort(p.Options.SortMethod)
	// save json
	if p.Options.OutputMode == JSON_OUTPUT {
		p.saveJSON(nodes, traffic, duration, successCount, linksCount)
	} else if p.Options.OutputMode == TEXT_OUTPUT {
		p.saveText(nodes)
	} else if p.Options.OutputMode == YAML_OUTPUT {
		p.saveYAML(nodes)
	} else {
		// render the result to pic
		p.renderPic(nodes, traffic, duration, successCount, linksCount)
	}
	return nodes, nil
}

func (p *ProfileTest) renderPic(nodes render.Nodes, traffic int64, duration string, successCount int, linksCount int) error {
	fontPath := "WenQuanYiMicroHei-01.ttf"
	options := render.NewTableOptions(40, 30, 0.5, 0.5, p.Options.FontSize, 0.5, fontPath, p.Options.Language, p.Options.Theme, "Asia/Shanghai", FontBytes)
	table, err := render.NewTableWithOption(nodes, &options)
	if err != nil {
		return err
	}
	// msg := fmt.Sprintf("Total Traffic : %s. Total Time : %s. Working Nodes: [%d/%d]", download.ByteCountIECTrim(traffic), duration, successCount, linksCount)
	msg := table.FormatTraffic(download.ByteCountIECTrim(traffic), duration, fmt.Sprintf("%d/%d", successCount, linksCount))
	if p.Options.OutputMode == PIC_PATH {
		table.Draw("out.png", msg)
		p.WriteMessage(getMsgByte(-1, "picdata", "out.png"))
		return nil
	}
	if picdata, err := table.EncodeB64(msg); err == nil {
		p.WriteMessage(getMsgByte(-1, "picdata", picdata))
	}
	return nil
}

func (p *ProfileTest) saveJSON(nodes render.Nodes, traffic int64, duration string, successCount int, linksCount int) error {
	jsonOutput := JSONOutput{
		Nodes:        nodes,
		Options:      *p.Options,
		Traffic:      traffic,
		Duration:     duration,
		SuccessCount: successCount,
		LinksCount:   linksCount,
	}
	data, err := json.MarshalIndent(&jsonOutput, "", "\t")
	if err != nil {
		return err
	}
	return ioutil.WriteFile("output.json", data, 0644)
}

func (p *ProfileTest) saveText(nodes render.Nodes) error {
	var links []string
	for _, node := range nodes {
		if node.Ping != "0" || node.AvgSpeed > 0 || node.MaxSpeed > 0 {
			links = append(links, node.Link)
		}
	}
	data := []byte(strings.Join(links, "\n"))
	return ioutil.WriteFile("output.txt", data, 0644)
}

func (p *ProfileTest) saveYAML(nodes render.Nodes) error {
	// Build proxies list from working nodes
	proxies := make([]map[string]interface{}, 0)
	usedNames := map[string]bool{}
	for _, node := range nodes {
		if !node.IsOk {
			continue
		}
		if len(strings.TrimSpace(node.Link)) < 1 {
			continue
		}
		uniqueName := makeUniqueProxyName(node.Remarks, usedNames)
		m, err := linkToClashProxy(node.Link, uniqueName)
		if err != nil {
			continue
		}
		proxies = append(proxies, m)
	}

	// Determine base file: use config.example.yaml template to keep exact sections
	configPath := "config.yaml"
	basePath := "config.example.yaml"
	if _, err := os.Stat(basePath); err != nil {
		// fallback to existing config.yaml if example template not found
		basePath = configPath
	}

	// Read template text
	raw, err := ioutil.ReadFile(basePath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")
	// find 'proxies:' top-level key
	proxiesIdx := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == "proxies:" && (len(line) == 8 || !strings.HasPrefix(line, " ")) {
			proxiesIdx = i
			break
		}
	}
	if proxiesIdx == -1 {
		// no proxies key; append one at end
		lines = append(lines, "proxies:")
		proxiesIdx = len(lines) - 1
		lines = append(lines, "")
	}
	// determine end of proxies block
	// Prefer explicit next section 'proxy-groups:' to avoid leaving residual entries
	endIdx := len(lines)
	for i := proxiesIdx + 1; i < len(lines); i++ {
		line := lines[i]
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && trim == "proxy-groups:" {
			endIdx = i
			break
		}
		// fallback: any next top-level key
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(trim, ":") {
			endIdx = i
			break
		}
	}
	// trim any trailing lone closing braces or templated proxy lines within proxies block
	for endIdx-1 > proxiesIdx+1 {
		lastLine := strings.TrimSpace(lines[endIdx-1])
		if lastLine == "}" || lastLine == "}," || strings.HasSuffix(lastLine, "}") || strings.HasPrefix(lastLine, "- {") {
			endIdx--
			continue
		}
		// stop at a clean boundary
		break
	}

	// Also update proxy-groups -> proxies arrays to contain all proxy names
	proxyNames := make([]string, 0, len(proxies))
	for _, m := range proxies {
		if n, ok := m["name"].(string); ok {
			proxyNames = append(proxyNames, n)
		}
	}
	// locate proxy-groups block
	groupsStart := -1
	groupsEnd := len(lines)
	for i, line := range lines {
		if strings.TrimSpace(line) == "proxy-groups:" && (len(line) == 13 || !strings.HasPrefix(line, " ")) {
			groupsStart = i
			break
		}
	}
	if groupsStart >= 0 {
		for i := groupsStart + 1; i < len(lines); i++ {
			t := strings.TrimSpace(lines[i])
			if t == "" {
				continue
			}
			if !strings.HasPrefix(lines[i], " ") && strings.HasSuffix(t, ":") {
				groupsEnd = i
				break
			}
		}
		// mutate lines between groupsStart and groupsEnd: replace any proxies: [...] blocks inline
		i := groupsStart + 1
		for i < groupsEnd {
			line := lines[i]
			idx := strings.Index(line, "proxies:")
			if idx >= 0 {
				// locate closing bracket ']' possibly on same or later line
				j := i
				closeIdx := strings.Index(line, "]")
				if closeIdx < 0 {
					j = i + 1
					for j < groupsEnd {
						closeIdx = strings.Index(lines[j], "]")
						if closeIdx >= 0 {
							break
						}
						j++
					}
				}
				// build new inline single-line proxies list preserving prefix/suffix
				prefix := line[:idx] + "proxies: ["
				suffix := ""
				if closeIdx >= 0 {
					suffix = lines[j][closeIdx+1:]
				}
				joined := make([]string, 0, len(proxyNames))
				for _, name := range proxyNames {
					joined = append(joined, formatYAMLScalar(name))
				}
				newLine := prefix + strings.Join(joined, ", ") + "]" + suffix
				// replace lines i..j (inclusive) with new single line
				front := append([]string{}, lines[:i]...)
				back := append([]string{}, lines[j+1:]...)
				lines = append(front, append([]string{newLine}, back...)...)
				// adjust bounds after replacement
				delta := 1 - (j + 1 - i)
				groupsEnd += delta
				if i < endIdx {
					endIdx += delta
				}
				// continue after the replaced line
				i++
				continue
			}
			i++
		}
	}

	// build new proxies block in single-line inline mapping style to match example
	var b strings.Builder
	if len(proxies) == 0 {
		// output an empty sequence to keep YAML valid
		b.WriteString("  []\n")
	} else {
		for idxProxy, m := range proxies {
			typ, _ := m["type"].(string)
			keyOrder := proxyKeyOrderForType(typ)
			if !contains(keyOrder, "name") {
				keyOrder = append([]string{"name"}, keyOrder...)
			}
			// collect parts in order, then remaining
			parts := make([]string, 0, len(m))
			for _, k := range keyOrder {
				if v, ok := m[k]; ok {
					parts = append(parts, k+": "+formatYAMLInline(v))
				}
			}
			for k, v := range m {
				if k == "type" || contains(keyOrder, k) {
					continue
				}
				parts = append(parts, k+": "+formatYAMLInline(v))
			}

			b.WriteString("  - { ")
			b.WriteString(strings.Join(parts, ", "))
			if idxProxy < len(proxies)-1 {
				b.WriteString(" }\n")
			} else {
				// last item: ensure newline then close brace without extra comma confusion
				b.WriteString(" }\n")
			}
		}
	}

	newBlock := b.String()

	// assemble new file content (replace exactly proxiesIdx..endIdx-1)
	var out strings.Builder
	out.WriteString(strings.Join(lines[:proxiesIdx+1], "\n"))
	out.WriteString("\n")
	out.WriteString(newBlock)
	out.WriteString(strings.Join(lines[endIdx:], "\n"))
	if !strings.HasSuffix(out.String(), "\n") {
		out.WriteString("\n")
	}

	return ioutil.WriteFile(configPath, []byte(out.String()), 0644)
}

func proxyKeyOrderForType(typ string) []string {
	switch typ {
	case "ss":
		return []string{"name", "type", "server", "port", "cipher", "password", "udp"}
	case "trojan":
		return []string{"name", "type", "server", "port", "password", "sni", "alpn", "skip-cert-verify", "udp", "network", "ws-opts", "grpc-opts"}
	case "vmess":
		return []string{"name", "type", "server", "port", "uuid", "alterId", "cipher", "tls", "network", "ws-path", "ws-headers", "http-opts", "h2-opts", "skip-cert-verify", "servername"}
	case "ssr":
		return []string{"name", "type", "server", "port", "cipher", "password", "protocol", "protocol-param", "obfs", "obfs-param", "udp"}
	case "http":
		return []string{"name", "type", "server", "port", "username", "password", "tls", "sni", "skip-cert-verify"}
	case "vless":
		return []string{"name", "type", "server", "port", "uuid", "sni", "network"}
	default:
		return []string{"name", "type", "server", "port"}
	}
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func formatYAMLScalar(v interface{}) string {
	switch val := v.(type) {
	case bool:
		if val {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case uint16:
		return strconv.Itoa(int(val))
	case float64:
		// avoid scientific notation
		return strconv.FormatFloat(val, 'f', -1, 64)
	case string:
		// leave safe plain scalars unquoted to mimic example style
		if isSafePlainYAML(val) {
			return val
		}
		// escape quotes
		s := strings.ReplaceAll(val, "\"", "\\\"")
		return "\"" + s + "\""
	default:
		// fallback to YAML marshal then trim newline
		b, _ := yaml.Marshal(val)
		s := strings.TrimSpace(string(b))
		return s
	}
}

func isSafePlainYAML(s string) bool {
	if s == "" {
		return false
	}
	// allow alphanum, dash, dot, underscore, colon, slash
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_' || r == ':' || r == '/' {
			continue
		}
		return false
	}
	return true
}

func leadingSpaces(s string) string {
	i := 0
	for i < len(s) && s[i] == ' ' {
		i++
	}
	return s[:i]
}

// formatYAMLInline renders basic types, []string, and map[string]string inline.
func formatYAMLInline(v interface{}) string {
	switch t := v.(type) {
	case []string:
		// inline array: [a, b]
		items := make([]string, 0, len(t))
		for _, it := range t {
			items = append(items, formatYAMLScalar(it))
		}
		return "[" + strings.Join(items, ", ") + "]"
	case map[string]string:
		// inline map: { k: v }
		kvs := make([]string, 0, len(t))
		for k, v := range t {
			kvs = append(kvs, k+": "+formatYAMLScalar(v))
		}
		sort.Strings(kvs)
		return "{" + strings.Join(kvs, ", ") + "}"
	default:
		return formatYAMLScalar(v)
	}
}

// ensure unique proxy names by suffixing with (n) when needed
func makeUniqueProxyName(base string, used map[string]bool) string {
	name := strings.TrimSpace(base)
	if name == "" {
		name = "Proxy"
	}
	if !used[name] {
		used[name] = true
		return name
	}
	// try name (2..)
	for i := 2; i < 10000; i++ {
		candidate := fmt.Sprintf("%s (%d)", name, i)
		if !used[candidate] {
			used[candidate] = true
			return candidate
		}
	}
	// fallback: append timestamp
	ts := time.Now().UnixNano()
	candidate := fmt.Sprintf("%s-%d", name, ts)
	used[candidate] = true
	return candidate
}

func linkToClashProxy(link string, name string) (map[string]interface{}, error) {
	matches, err := utils.CheckLink(link)
	if err != nil || len(matches) < 2 {
		return nil, err
	}
	scheme := strings.ToLower(matches[1])
	switch scheme {
	case "vmess":
		opt, err := config.VmessLinkToVmessOption(link)
		if err != nil {
			return nil, err
		}
		m := map[string]interface{}{
			"name":   name,
			"type":   "vmess",
			"server": opt.Server,
			"port":   int(opt.Port),
		}
		id := opt.UUID
		if id == "" {
			id = opt.Password
		}
		if id != "" {
			m["uuid"] = id
		}
		// always include alterId, default to 0 when absent
		m["alterId"] = opt.AlterID
		if opt.Cipher != "" {
			m["cipher"] = opt.Cipher
		}
		if opt.TLS {
			m["tls"] = true
		}
		if opt.Network != "" {
			m["network"] = opt.Network
		}
		if opt.WSPath != "" {
			m["ws-path"] = opt.WSPath
		}
		if len(opt.WSHeaders) > 0 {
			m["ws-headers"] = opt.WSHeaders
		}
		if opt.SkipCertVerify {
			m["skip-cert-verify"] = opt.SkipCertVerify
		}
		if opt.ServerName != "" {
			m["servername"] = opt.ServerName
		}
		if opt.HTTPOpts.Method != "" || len(opt.HTTPOpts.Path) > 0 || len(opt.HTTPOpts.Headers) > 0 {
			httpOpts := map[string]interface{}{}
			if opt.HTTPOpts.Method != "" {
				httpOpts["method"] = opt.HTTPOpts.Method
			}
			if len(opt.HTTPOpts.Path) > 0 {
				httpOpts["path"] = opt.HTTPOpts.Path
			}
			if len(opt.HTTPOpts.Headers) > 0 {
				httpOpts["headers"] = opt.HTTPOpts.Headers
			}
			m["http-opts"] = httpOpts
		}
		if len(opt.HTTP2Opts.Host) > 0 || opt.HTTP2Opts.Path != "" {
			h2 := map[string]interface{}{}
			if len(opt.HTTP2Opts.Host) > 0 {
				h2["host"] = opt.HTTP2Opts.Host
			}
			if opt.HTTP2Opts.Path != "" {
				h2["path"] = opt.HTTP2Opts.Path
			}
			m["h2-opts"] = h2
		}
		if opt.WSOpts.Path != "" || len(opt.WSOpts.Headers) > 0 || opt.WSOpts.MaxEarlyData != 0 || opt.WSOpts.EarlyDataHeaderName != "" {
			ws := map[string]interface{}{}
			if opt.WSOpts.Path != "" {
				ws["path"] = opt.WSOpts.Path
			}
			if len(opt.WSOpts.Headers) > 0 {
				ws["headers"] = opt.WSOpts.Headers
			}
			if opt.WSOpts.MaxEarlyData != 0 {
				ws["max-early-data"] = opt.WSOpts.MaxEarlyData
			}
			if opt.WSOpts.EarlyDataHeaderName != "" {
				ws["early-data-header-name"] = opt.WSOpts.EarlyDataHeaderName
			}
			m["ws-opts"] = ws
		}
		return m, nil
	case "trojan":
		opt, err := config.TrojanLinkToTrojanOption(link)
		if err != nil {
			return nil, err
		}
		m := map[string]interface{}{
			"name":     name,
			"type":     "trojan",
			"server":   opt.Server,
			"port":     opt.Port,
			"password": opt.Password,
		}
		if len(opt.ALPN) > 0 {
			m["alpn"] = opt.ALPN
		}
		if opt.SNI != "" {
			m["sni"] = opt.SNI
		}
		if opt.SkipCertVerify {
			m["skip-cert-verify"] = opt.SkipCertVerify
		}
		if opt.UDP {
			m["udp"] = true
		}
		if opt.Network != "" {
			m["network"] = opt.Network
		}
		if opt.WSOpts.Path != "" || len(opt.WSOpts.Headers) > 0 {
			ws := map[string]interface{}{}
			if opt.WSOpts.Path != "" {
				ws["path"] = opt.WSOpts.Path
			}
			if len(opt.WSOpts.Headers) > 0 {
				ws["headers"] = opt.WSOpts.Headers
			}
			m["ws-opts"] = ws
		}
		if opt.GrpcOpts.GrpcServiceName != "" {
			m["grpc-opts"] = map[string]interface{}{"grpc-service-name": opt.GrpcOpts.GrpcServiceName}
		}
		return m, nil
	case "ss":
		opt, err := config.SSLinkToSSOption(link)
		if err != nil {
			return nil, err
		}
		m := map[string]interface{}{
			"name":     name,
			"type":     "ss",
			"server":   opt.Server,
			"port":     opt.Port,
			"cipher":   opt.Cipher,
			"password": opt.Password,
		}
		if opt.UDP {
			m["udp"] = true
		}
		if opt.Plugin != "" {
			m["plugin"] = opt.Plugin
		}
		if len(opt.PluginOpts) > 0 {
			m["plugin-opts"] = opt.PluginOpts
		}
		return m, nil
	case "ssr":
		opt, err := config.SSRLinkToSSROption(link)
		if err != nil {
			return nil, err
		}
		m := map[string]interface{}{
			"name":     name,
			"type":     "ssr",
			"server":   opt.Server,
			"port":     opt.Port,
			"cipher":   opt.Cipher,
			"password": opt.Password,
			"protocol": opt.Protocol,
			"obfs":     opt.Obfs,
		}
		if opt.ObfsParam != "" {
			m["obfs-param"] = opt.ObfsParam
		}
		if opt.ProtocolParam != "" {
			m["protocol-param"] = opt.ProtocolParam
		}
		if opt.UDP {
			m["udp"] = true
		}
		return m, nil
	case "http":
		opt, err := config.HttpLinkToHttpOption(link)
		if err != nil {
			return nil, err
		}
		m := map[string]interface{}{
			"name":   name,
			"type":   "http",
			"server": opt.Server,
			"port":   opt.Port,
		}
		if opt.UserName != "" {
			m["username"] = opt.UserName
		}
		if opt.Password != "" {
			m["password"] = opt.Password
		}
		if opt.TLS {
			m["tls"] = true
		}
		if opt.SNI != "" {
			m["sni"] = opt.SNI
		}
		if opt.SkipCertVerify {
			m["skip-cert-verify"] = opt.SkipCertVerify
		}
		return m, nil
	case "vless":
		cfg, err := config.Link2Config(link)
		if err != nil {
			return nil, err
		}
		m := map[string]interface{}{
			"name":   name,
			"type":   "vless",
			"server": cfg.Server,
			"port":   cfg.Port,
		}
		if cfg.Password != "" {
			m["uuid"] = cfg.Password
		}
		if cfg.SNI != "" {
			m["sni"] = cfg.SNI
		}
		if cfg.Net != "" {
			m["network"] = cfg.Net
		}
		return m, nil
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", scheme)
	}
}

func (p *ProfileTest) testOne(ctx context.Context, index int, link string, nodeChan chan<- render.Node, trafficChan chan<- int64) error {
	// panic
	defer p.wg.Done()
	if link == "" {
		link = p.Links[index]
		link = strings.SplitN(link, "^", 2)[0]
	}
	cfg, err := config.Link2Config(link)
	if err != nil {
		return err
	}
	remarks := cfg.Remarks
	if err != nil || remarks == "" {
		remarks = fmt.Sprintf("Profile %d", index)
	}
	protocol := cfg.Protocol
	if (cfg.Protocol == "vmess" || cfg.Protocol == "trojan") && cfg.Net != "" {
		protocol = fmt.Sprintf("%s/%s", cfg.Protocol, cfg.Net)
	}
	elapse, err := p.pingLink(index, link)
	log.Printf("%d %s elapse: %dms", index, remarks, elapse)
	if err != nil {
		node := render.Node{
			Id:       index,
			Group:    p.Options.GroupName,
			Remarks:  remarks,
			Protocol: protocol,
			Ping:     fmt.Sprintf("%d", elapse),
			AvgSpeed: 0,
			MaxSpeed: 0,
			IsOk:     elapse > 0,
		}
		nodeChan <- node
		return err
	}
	err = p.WriteMessage(getMsgByte(index, "startspeed"))
	ch := make(chan int64, 1)
	startCh := make(chan time.Time, 1)
	defer close(ch)
	go func(ch <-chan int64, startChan <-chan time.Time) {
		var max int64
		var sum int64
		var avg int64
		start := time.Now()
	Loop:
		for {
			select {
			case speed, ok := <-ch:
				if !ok || speed < 0 {
					break Loop
				}
				sum += speed
				duration := float64(time.Since(start)/time.Millisecond) / float64(1000)
				avg = int64(float64(sum) / duration)
				if max < speed {
					max = speed
				}
				log.Printf("%d %s recv: %s", index, remarks, download.ByteCountIEC(speed))
				err = p.WriteMessage(getMsgByte(index, "gotspeed", avg, max, speed))
				if trafficChan != nil {
					trafficChan <- speed
				}
			case s := <-startChan:
				start = s
			case <-ctx.Done():
				log.Printf("index %d done!", index)
				break Loop
			}
		}
		node := render.Node{
			Id:       index,
			Group:    p.Options.GroupName,
			Remarks:  remarks,
			Protocol: protocol,
			Ping:     fmt.Sprintf("%d", elapse),
			AvgSpeed: avg,
			MaxSpeed: max,
			IsOk:     true,
			Traffic:  sum,
		}
		nodeChan <- node
	}(ch, startCh)
	speed, err := download.Download(link, p.Options.Timeout, p.Options.Timeout, ch, startCh)
	// speed, err := download.DownloadRange(link, 2, p.Options.Timeout, p.Options.Timeout, ch, startCh)
	if speed < 1 {
		p.WriteMessage(getMsgByte(index, "gotspeed", -1, -1, 0))
	}
	return err
}

func (p *ProfileTest) pingLink(index int, link string) (int64, error) {
	if p.Options.SpeedTestMode == SpeedOnly {
		return 0, nil
	}
	if link == "" {
		link = p.Links[index]
	}
	p.WriteMessage(getMsgByte(index, "startping"))
	elapse, err := request.PingLink(link, 2)
	p.WriteMessage(getMsgByte(index, "gotping", elapse))
	if elapse < 1 {
		p.WriteMessage(getMsgByte(index, "gotspeed", -1, -1, 0))
		return 0, err
	}
	if p.Options.SpeedTestMode == PingOnly {
		p.WriteMessage(getMsgByte(index, "gotspeed", -1, -1, 0))
		return elapse, errors.New(PingOnly)
	}
	return elapse, err
}

func FormatDuration(duration time.Duration) string {
	h := duration / time.Hour
	duration -= h * time.Hour
	m := duration / time.Minute
	duration -= m * time.Minute
	s := duration / time.Second
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	return fmt.Sprintf("%dm %ds", m, s)
}

func png2base64(path string) (string, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(bytes), nil
}

func isYamlFile(filePath string) bool {
	return strings.HasSuffix(filePath, ".yaml") || strings.HasSuffix(filePath, ".yml")
}

// api
func PeekClash(input string, n int) ([]string, error) {
	scanner := bufio.NewScanner(strings.NewReader(input))
	proxiesStart := false
	data := []byte{}
	linkCount := 0
	for scanner.Scan() {
		b := scanner.Bytes()
		trimLine := strings.TrimSpace(string(b))
		if trimLine == "proxy-groups:" || trimLine == "rules:" || trimLine == "Proxy Group:" {
			break
		}
		if proxiesStart {
			if _, err := config.ParseBaseProxy(trimLine); err != nil {
				continue
			}
			if strings.HasPrefix(trimLine, "-") {
				if linkCount >= n {
					break
				}
				linkCount += 1
			}
			data = append(data, b...)
			data = append(data, byte('\n'))
			continue
		}
		if !proxiesStart && (trimLine == "proxies:" || trimLine == "Proxy:") {
			proxiesStart = true
			b = []byte("proxies:")
		}
		data = append(data, b...)
		data = append(data, byte('\n'))
	}
	// fmt.Println(string(data))
	links, err := parseClashByte(data)
	if err != nil || len(links) < 1 {
		return []string{}, err
	}
	endIndex := n
	if endIndex > len(links) {
		endIndex = len(links)
	}
	return links[:endIndex], nil
}
