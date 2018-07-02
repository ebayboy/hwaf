package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"  /* structured logger lib */
	"github.com/flier/gohs/hyperscan" /* Hyperscan lib */
	"github.com/spf13/cobra"          /* CLI lib */
	"github.com/spf13/viper"          /* Configuration lib */
	"github.com/valyala/fasthttp"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// with sync for resource lock
type scratch struct {
	sync.RWMutex
	s *hyperscan.Scratch
}

var (
	Version  string
	Debug    bool
	Port     int
	FilePath string
	Flag     string
	Scratch  scratch
	Db       hyperscan.BlockDatabase
	Uptime   time.Time
	RegexMap map[int]RegexLine
)

/* not match resp */
type Response struct {
	Errno int         `json:errno`
	Msg   string      `json:msg`
	Data  interface{} `json:data`
}

/* match resp */
type MatchResp struct {
	Id         int       `json:id`
	From       int       `json:from`
	To         int       `json:to`
	Flags      int       `json:flags`
	Context    string    `json:context`
	RegexLinev RegexLine `json:regexline`
}

type RegexLine struct {
	Expr string
	Data string
}

func main() {
	Version = "0.0.1"
	viper.AutomaticEnv()
	var rootCmd = &cobra.Command{
		Use:     "gohs-ladon",
		Short:   fmt.Sprintf("Gohs-ladon Service %s", Version),
		Run:     run,
		PreRunE: preRunE,
	}
	rootCmd.Flags().Bool("debug", false, "Enable debug mode")
	rootCmd.Flags().Int("port", 8080, "Listen port")
	rootCmd.Flags().String("filepath", "", "Dict file path")
	rootCmd.Flags().String("flag", "iou", "Regex Flag")

	viper.BindPFlag("debug", rootCmd.Flags().Lookup("debug"))
	viper.BindPFlag("port", rootCmd.Flags().Lookup("port"))
	viper.BindPFlag("filepath", rootCmd.Flags().Lookup("filepath"))
	viper.BindPFlag("flag", rootCmd.Flags().Lookup("flag"))

	rootCmd.Execute()
}

func run(cmd *cobra.Command, args []string) {
	addr := fmt.Sprintf("0.0.0.0:%d", Port)

	Uptime = time.Now()
	fmt.Printf("[%s] gohs-ladon %s Running on %s\n", Uptime.Format(time.RFC3339), Version, addr)

	h := requestHandler
	if err := fasthttp.ListenAndServe(addr, h); err != nil {
		log.Fatalf("Error in ListenAndServe: %s", err)
	}
}

func preRunE(cmd *cobra.Command, args []string) error {
	Debug = viper.GetBool("debug")
	Port = viper.GetInt("port")
	FilePath = viper.GetString("filepath")
	Flag = viper.GetString("flag")

	if FilePath == "" {
		return fmt.Errorf("empty regex filepath")
	}
	if Debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	log.Debug("Prerun", args)
	RegexMap = make(map[int]RegexLine)
	err := buildScratch(FilePath)
	return err
}

// build scratch for regex file.
func buildScratch(filepath string) (err error) {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	patterns := []*hyperscan.Pattern{}
	var expr hyperscan.Expression
	var id int
	//flags := Flag
	//flags := hyperscan.Caseless | hyperscan.Utf8Mode
	flags, err := hyperscan.ParseCompileFlag(Flag)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {

		log.Debug(scanner.Text())
		line := scanner.Text()

		// line start with #, skip
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			log.Info(fmt.Sprintf("line start with #, skip line: %s", line))
			continue
		}
		s := strings.Split(line, "\t")

		// length less than 3, skip
		if len(s) < 3 {
			log.Info(fmt.Sprintf("line length less than 3, skip line: [%s] len(s):[%d]", line, len(s)))
			continue
		}

		/* id */
		id, err = strconv.Atoi(s[0])
		if err != nil {
			return fmt.Errorf("Atoi error.")
		}

		/* regex */
		expr = hyperscan.Expression(s[1])

		/* data */
		data := s[2]
		pattern := &hyperscan.Pattern{Expression: expr, Flags: flags, Id: id}
		patterns = append(patterns, pattern)
		RegexMap[id] = RegexLine{string(expr), data}
	}

	if len(patterns) <= 0 {
		return fmt.Errorf("Empty regex")
	}
	log.Info(fmt.Sprintf("regex file line number: %d", len(patterns)))
	log.Info("Start Building, please wait...")
	db, err := hyperscan.NewBlockDatabase(patterns...)
	Db = db

	if err != nil {
		return err
	}
	scratch, err := hyperscan.NewScratch(Db)
	if err != nil {
		return err
	}
	Scratch.s = scratch

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		end := time.Now()
		latency := end.Sub(start)
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		log.WithFields(log.Fields{
			"remote_addr":    host,
			"latency":        latency,
			"content_length": r.ContentLength,
		}).Info(fmt.Sprintf("%s %s", r.Method, r.RequestURI))
	})
}

func matchHandle(w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("q")
	var resp Response = Response{Errno: 0}
	w.Header().Set("Content-Type", "application/json")
	if query == "" {
		resp.Errno = -1
		resp.Msg = "empty param q"
	} else {
		inputData := []byte(query)
		// results
		var matchResps []MatchResp
		eventHandler := func(id uint, from, to uint64, flags uint, context interface{}) error {
			log.Info(fmt.Sprintf("id: %d, from: %d, to: %d, flags: %v, context: %s", id, from, to, flags, context))
			regexLine, ok := RegexMap[int(id)]
			if !ok {
				regexLine = RegexLine{}
			}
			matchResp := MatchResp{Id: int(id), From: int(from), To: int(to), Flags: int(flags), Context: fmt.Sprintf("%s", context), RegexLinev: regexLine}
			matchResps = append(matchResps, matchResp)
			return nil
		}

		// lock scratch
		Scratch.Lock()
		if err := Db.Scan(inputData, Scratch.s, eventHandler, inputData); err != nil {
			logFields := log.Fields{"query": query}
			log.WithFields(logFields).Error(err)
			resp.Errno = -2
			resp.Msg = fmt.Sprintf("Db.Scan error: %s", err)
		} else {
			if len(matchResps) <= 0 {
				resp.Errno = 1
				resp.Msg = "no match"
			}
			resp.Data = matchResps
		}
		// unlock scratch
		Scratch.Unlock()
	}
	json.NewEncoder(w).Encode(resp)
	w.WriteHeader(http.StatusOK)
}

func statsHandle(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, fmt.Sprintf("gohs-ladon %v, Uptime %v",
		Version, Uptime.Format(time.RFC3339)))
}

func requestHandler(ctx *fasthttp.RequestCtx) {
	fmt.Fprintf(ctx, "Hello, world!\n\n")

	fmt.Fprintf(ctx, "Request method is %q\n", ctx.Method())
	fmt.Fprintf(ctx, "RequestURI is %q\n", ctx.RequestURI())
	fmt.Fprintf(ctx, "Requested path is %q\n", ctx.Path())
	fmt.Fprintf(ctx, "Host is %q\n", ctx.Host())
	fmt.Fprintf(ctx, "Query string is %q\n", ctx.QueryArgs())
	fmt.Fprintf(ctx, "User-Agent is %q\n", ctx.UserAgent())
	fmt.Fprintf(ctx, "Connection has been established at %s\n", ctx.ConnTime())
	fmt.Fprintf(ctx, "Request has been started at %s\n", ctx.Time())
	fmt.Fprintf(ctx, "Serial request number for the current connection is %d\n", ctx.ConnRequestNum())
	fmt.Fprintf(ctx, "Your ip is %q\n\n", ctx.RemoteIP())

	fmt.Fprintf(ctx, "Raw request is:\n---CUT---\n%s\n---CUT---", &ctx.Request)

	ctx.SetContentType("text/plain; charset=utf8")

	// Set arbitrary headers
	ctx.Response.Header.Set("X-My-Header", "my-header-value")

	// Set cookies
	var c fasthttp.Cookie
	c.SetKey("cookie-name")
	c.SetValue("cookie-value")
	ctx.Response.Header.SetCookie(&c)
}
