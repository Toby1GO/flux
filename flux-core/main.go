package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	_ "modernc.org/sqlite"
)

const (
	okMessage       = "操作成功"
	defaultDBPath   = "./data/panel.db"
	defaultListen   = ":6365"
	defaultJWT      = "change-me"
	bytesToGB       = 1024 * 1024 * 1024
	serviceNameZero = "0"
)

type Config struct {
	ListenAddr      string
	AgentListenAddr string
	DBPath          string
	JWTSecret       string
	PublicAddr      string
	AgentPublicAddr string
	AgentInstallURL string
	AgentReleaseURL string
	StaticDir       string
}

type App struct {
	cfg      Config
	db       *sql.DB
	upgrader websocket.Upgrader

	mu       sync.RWMutex
	nodes    map[int64]*NodeSession
	admins   map[*websocket.Conn]bool
	adminMux map[*websocket.Conn]*sync.Mutex
}

type NodeSession struct {
	ID      int64
	Secret  string
	Conn    *websocket.Conn
	WriteMu sync.Mutex

	PendingMu sync.Mutex
	Pending   map[string]chan CommandResponse
}

type APIResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	TS   int64  `json:"ts"`
	Data any    `json:"data"`
}

type Claims struct {
	Sub    string `json:"sub"`
	RoleID int    `json:"role_id"`
	User   string `json:"user"`
	Exp    int64  `json:"exp"`
	Iat    int64  `json:"iat"`
}

type CurrentUser struct {
	ID     int64
	RoleID int
	Name   string
}

type ctxKey string

const currentUserKey ctxKey = "currentUser"

type CommandResponse struct {
	Type      string          `json:"type"`
	Success   bool            `json:"success"`
	Message   string          `json:"message"`
	Data      json.RawMessage `json:"data,omitempty"`
	RequestID string          `json:"requestId,omitempty"`
}

type encryptedMessage struct {
	Encrypted bool   `json:"encrypted"`
	Data      string `json:"data"`
	Timestamp int64  `json:"timestamp"`
}

func main() {
	cfg := loadConfig()

	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0755); err != nil && filepath.Dir(cfg.DBPath) != "." {
		log.Fatalf("create data dir: %v", err)
	}

	db, err := sql.Open("sqlite", cfg.DBPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	app := &App{
		cfg: cfg,
		db:  db,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		nodes:    make(map[int64]*NodeSession),
		admins:   make(map[*websocket.Conn]bool),
		adminMux: make(map[*websocket.Conn]*sync.Mutex),
	}

	if err := app.migrate(); err != nil {
		log.Fatalf("migrate sqlite: %v", err)
	}
	app.enforceExpiredForwards()
	go app.expiryLoop()

	if cfg.AgentListenAddr != "" && strings.TrimSpace(cfg.AgentListenAddr) != strings.TrimSpace(cfg.ListenAddr) {
		go func() {
			log.Printf("flux-agent gateway listening on %s", cfg.AgentListenAddr)
			if err := http.ListenAndServe(cfg.AgentListenAddr, app.agentRoutes()); err != nil {
				log.Fatalf("agent gateway listen: %v", err)
			}
		}()
	}

	log.Printf("flux-core listening on %s, db=%s", cfg.ListenAddr, cfg.DBPath)
	if err := http.ListenAndServe(cfg.ListenAddr, app.routes()); err != nil {
		log.Fatal(err)
	}
}

func loadConfig() Config {
	addr := env("FLUX_CORE_ADDR", "")
	if addr == "" {
		if port := os.Getenv("PORT"); port != "" {
			addr = ":" + port
		} else {
			addr = defaultListen
		}
	}
	return Config{
		ListenAddr:      addr,
		AgentListenAddr: os.Getenv("FLUX_AGENT_ADDR"),
		DBPath:          env("FLUX_DB_PATH", defaultDBPath),
		JWTSecret:       env("JWT_SECRET", defaultJWT),
		PublicAddr:      os.Getenv("PUBLIC_ADDR"),
		AgentPublicAddr: env("AGENT_PUBLIC_ADDR", os.Getenv("PUBLIC_ADDR")),
		AgentInstallURL: os.Getenv("AGENT_INSTALL_URL"),
		AgentReleaseURL: os.Getenv("AGENT_RELEASE_URL"),
		StaticDir:       os.Getenv("STATIC_DIR"),
	}
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()

	a.registerAgentRoutes(mux)

	mux.HandleFunc("/api/v1/captcha/check", a.wrapPublic(a.handleCaptchaCheck))
	mux.HandleFunc("/api/v1/captcha/generate", a.wrapPublic(a.handleCaptchaGenerate))
	mux.HandleFunc("/api/v1/captcha/verify", a.wrapPublic(a.handleCaptchaVerify))
	mux.HandleFunc("/api/v1/user/login", a.wrapPublic(a.handleLogin))
	mux.HandleFunc("/api/v1/open_api/sub_store", a.wrapPublic(a.handleOpenSubStore))
	mux.HandleFunc("/api/v1/config/get", a.wrapPublic(a.handleConfigGet))

	mux.HandleFunc("/api/v1/user/create", a.wrapAdmin(a.handleUserCreate))
	mux.HandleFunc("/api/v1/user/list", a.wrapAdmin(a.handleUserList))
	mux.HandleFunc("/api/v1/user/update", a.wrapAdmin(a.handleUserUpdate))
	mux.HandleFunc("/api/v1/user/delete", a.wrapAdmin(a.handleUserDelete))
	mux.HandleFunc("/api/v1/user/reset", a.wrapAdmin(a.handleUserReset))
	mux.HandleFunc("/api/v1/user/package", a.wrapAuth(a.handleUserPackage))
	mux.HandleFunc("/api/v1/user/updatePassword", a.wrapAuth(a.handleUpdatePassword))

	mux.HandleFunc("/api/v1/config/list", a.wrapAuth(a.handleConfigList))
	mux.HandleFunc("/api/v1/config/update", a.wrapAdmin(a.handleConfigUpdate))
	mux.HandleFunc("/api/v1/config/update-single", a.wrapAdmin(a.handleConfigUpdateSingle))

	mux.HandleFunc("/api/v1/node/create", a.wrapAdmin(a.handleNodeCreate))
	mux.HandleFunc("/api/v1/node/list", a.wrapAdmin(a.handleNodeList))
	mux.HandleFunc("/api/v1/node/update", a.wrapAdmin(a.handleNodeUpdate))
	mux.HandleFunc("/api/v1/node/delete", a.wrapAdmin(a.handleNodeDelete))
	mux.HandleFunc("/api/v1/node/install", a.wrapAdmin(a.handleNodeInstall))

	mux.HandleFunc("/api/v1/tunnel/create", a.wrapAdmin(a.handleTunnelCreate))
	mux.HandleFunc("/api/v1/tunnel/list", a.wrapAdmin(a.handleTunnelList))
	mux.HandleFunc("/api/v1/tunnel/update", a.wrapAdmin(a.handleTunnelUpdate))
	mux.HandleFunc("/api/v1/tunnel/delete", a.wrapAdmin(a.handleTunnelDelete))
	mux.HandleFunc("/api/v1/tunnel/user/assign", a.wrapAdmin(a.handleUserTunnelAssign))
	mux.HandleFunc("/api/v1/tunnel/user/list", a.wrapAdmin(a.handleUserTunnelList))
	mux.HandleFunc("/api/v1/tunnel/user/remove", a.wrapAdmin(a.handleUserTunnelRemove))
	mux.HandleFunc("/api/v1/tunnel/user/update", a.wrapAdmin(a.handleUserTunnelUpdate))
	mux.HandleFunc("/api/v1/tunnel/user/tunnel", a.wrapAuth(a.handleUsableTunnels))
	mux.HandleFunc("/api/v1/tunnel/diagnose", a.wrapAuth(a.handleTunnelDiagnose))

	mux.HandleFunc("/api/v1/forward/create", a.wrapAuth(a.handleForwardCreate))
	mux.HandleFunc("/api/v1/forward/list", a.wrapAuth(a.handleForwardList))
	mux.HandleFunc("/api/v1/forward/update", a.wrapAuth(a.handleForwardUpdate))
	mux.HandleFunc("/api/v1/forward/delete", a.wrapAuth(a.handleForwardDelete))
	mux.HandleFunc("/api/v1/forward/force-delete", a.wrapAuth(a.handleForwardForceDelete))
	mux.HandleFunc("/api/v1/forward/pause", a.wrapAuth(a.handleForwardPause))
	mux.HandleFunc("/api/v1/forward/resume", a.wrapAuth(a.handleForwardResume))
	mux.HandleFunc("/api/v1/forward/diagnose", a.wrapAuth(a.handleForwardDiagnose))
	mux.HandleFunc("/api/v1/forward/update-order", a.wrapAuth(a.handleForwardOrder))

	mux.HandleFunc("/api/v1/speed-limit/create", a.wrapAdmin(a.handleSpeedLimitCreate))
	mux.HandleFunc("/api/v1/speed-limit/list", a.wrapAdmin(a.handleSpeedLimitList))
	mux.HandleFunc("/api/v1/speed-limit/update", a.wrapAdmin(a.handleSpeedLimitUpdate))
	mux.HandleFunc("/api/v1/speed-limit/delete", a.wrapAdmin(a.handleSpeedLimitDelete))

	if a.cfg.StaticDir != "" {
		mux.HandleFunc("/", a.handleStatic)
	}

	return a.withCORS(mux)
}

func (a *App) agentRoutes() http.Handler {
	mux := http.NewServeMux()
	a.registerAgentRoutes(mux)
	return a.withCORS(mux)
}

func (a *App) registerAgentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/flow/test", a.wrapPublic(a.handleFlowTest))
	mux.HandleFunc("/flow/upload", a.wrapPublic(a.handleFlowUpload))
	mux.HandleFunc("/flow/config", a.wrapPublic(a.handleFlowConfig))
	mux.HandleFunc("/system-info", a.handleSystemInfo)
}

func (a *App) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.cors(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) cors(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Expose-Headers", "Authorization")
}

func (a *App) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}

	root, err := filepath.Abs(a.cfg.StaticDir)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	rel := strings.TrimPrefix(filepath.Clean("/"+r.URL.Path), string(filepath.Separator))
	if rel == "" || rel == "." {
		rel = "index.html"
	}
	target := filepath.Join(root, rel)
	absTarget, err := filepath.Abs(target)
	if err != nil || (absTarget != root && !strings.HasPrefix(absTarget, root+string(filepath.Separator))) {
		http.NotFound(w, r)
		return
	}

	if info, err := os.Stat(absTarget); err == nil && !info.IsDir() {
		http.ServeFile(w, r, absTarget)
		return
	}

	http.ServeFile(w, r, filepath.Join(root, "index.html"))
}

func (a *App) wrapPublic(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(w, r)
	}
}

func (a *App) wrapAuth(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := a.authenticate(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, APIResponse{Code: 401, Msg: "未登录或token已过期", TS: nowMS(), Data: nil})
			return
		}
		ctx := context.WithValue(r.Context(), currentUserKey, u)
		fn(w, r.WithContext(ctx))
	}
}

func (a *App) wrapAdmin(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return a.wrapAuth(func(w http.ResponseWriter, r *http.Request) {
		if currentUser(r).RoleID != 0 {
			fail(w, 403, "权限不足，仅管理员可操作")
			return
		}
		fn(w, r)
	})
}

func currentUser(r *http.Request) CurrentUser {
	if v, ok := r.Context().Value(currentUserKey).(CurrentUser); ok {
		return v
	}
	return CurrentUser{}
}

func (a *App) authenticate(r *http.Request) (CurrentUser, bool) {
	token := strings.TrimSpace(r.Header.Get("Authorization"))
	if token == "" {
		return CurrentUser{}, false
	}
	claims, err := a.parseToken(token)
	if err != nil {
		return CurrentUser{}, false
	}
	id, _ := strconv.ParseInt(claims.Sub, 10, 64)
	return CurrentUser{ID: id, RoleID: claims.RoleID, Name: claims.User}, true
}

func ok(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, APIResponse{Code: 0, Msg: okMessage, TS: nowMS(), Data: data})
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, http.StatusOK, APIResponse{Code: code, Msg: msg, TS: nowMS(), Data: nil})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 10<<20))
	dec.UseNumber()
	return dec.Decode(dst)
}

func readMap(r *http.Request) (map[string]any, error) {
	var m map[string]any
	err := readJSON(r, &m)
	if m == nil {
		m = map[string]any{}
	}
	return m, err
}

func nowMS() int64 {
	return time.Now().UnixMilli()
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func (a *App) signToken(userID int64, roleID int, name string) (string, error) {
	claims := Claims{
		Sub:    strconv.FormatInt(userID, 10),
		RoleID: roleID,
		User:   name,
		Iat:    time.Now().Unix(),
		Exp:    time.Now().Add(7 * 24 * time.Hour).Unix(),
	}
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(claims)
	head := base64.RawURLEncoding.EncodeToString(h)
	body := base64.RawURLEncoding.EncodeToString(p)
	unsigned := head + "." + body
	mac := hmac.New(sha256.New, []byte(a.cfg.JWTSecret))
	mac.Write([]byte(unsigned))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return unsigned + "." + sig, nil
}

func (a *App) parseToken(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("bad token")
	}
	unsigned := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, err
	}
	mac := hmac.New(sha256.New, []byte(a.cfg.JWTSecret))
	mac.Write([]byte(unsigned))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return Claims{}, errors.New("bad signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, err
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, err
	}
	if c.Exp <= time.Now().Unix() {
		return Claims{}, errors.New("expired")
	}
	return c, nil
}

func (a *App) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS forward (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			user_name VARCHAR(100) NOT NULL,
			name VARCHAR(100) NOT NULL,
			tunnel_id INTEGER NOT NULL,
			remote_addr TEXT NOT NULL,
			strategy VARCHAR(100) NOT NULL DEFAULT 'fifo',
			flow INTEGER NOT NULL DEFAULT 0,
			exp_time INTEGER NOT NULL DEFAULT 0,
			in_flow INTEGER NOT NULL DEFAULT 0,
			out_flow INTEGER NOT NULL DEFAULT 0,
			created_time INTEGER NOT NULL,
			updated_time INTEGER NOT NULL,
			status INTEGER NOT NULL,
			inx INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS forward_port (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			forward_id INTEGER NOT NULL,
			node_id INTEGER NOT NULL,
			port INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS node (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name VARCHAR(100) NOT NULL,
			secret VARCHAR(100) NOT NULL,
			server_ip VARCHAR(100) NOT NULL,
			port TEXT NOT NULL,
			interface_name VARCHAR(200),
			version VARCHAR(100),
			http INTEGER NOT NULL DEFAULT 0,
			tls INTEGER NOT NULL DEFAULT 0,
			socks INTEGER NOT NULL DEFAULT 0,
			created_time INTEGER NOT NULL,
			updated_time INTEGER,
			status INTEGER NOT NULL,
			tcp_listen_addr VARCHAR(100) NOT NULL DEFAULT '[::]',
			udp_listen_addr VARCHAR(100) NOT NULL DEFAULT '[::]',
			exp_time INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS speed_limit (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name VARCHAR(100) NOT NULL,
			speed INTEGER NOT NULL,
			tunnel_id INTEGER NOT NULL,
			tunnel_name VARCHAR(100) NOT NULL,
			created_time INTEGER NOT NULL,
			updated_time INTEGER,
			status INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS statistics_flow (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			flow INTEGER NOT NULL,
			total_flow INTEGER NOT NULL,
			time VARCHAR(100) NOT NULL,
			created_time INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS tunnel (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name VARCHAR(100) NOT NULL,
			traffic_ratio REAL NOT NULL DEFAULT 1.0,
			type INTEGER NOT NULL,
			protocol VARCHAR(10) NOT NULL DEFAULT 'tls',
			flow INTEGER NOT NULL,
			created_time INTEGER NOT NULL,
			updated_time INTEGER NOT NULL,
			status INTEGER NOT NULL,
			in_ip TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS chain_tunnel (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			tunnel_id INTEGER NOT NULL,
			chain_type INTEGER NOT NULL,
			node_id INTEGER NOT NULL,
			port INTEGER,
			strategy VARCHAR(10),
			inx INTEGER,
			protocol VARCHAR(10)
		)`,
		`CREATE TABLE IF NOT EXISTS user (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user VARCHAR(100) NOT NULL UNIQUE,
			pwd VARCHAR(100) NOT NULL,
			role_id INTEGER NOT NULL,
			exp_time INTEGER NOT NULL,
			flow INTEGER NOT NULL,
			in_flow INTEGER NOT NULL DEFAULT 0,
			out_flow INTEGER NOT NULL DEFAULT 0,
			flow_reset_time INTEGER NOT NULL,
			num INTEGER NOT NULL,
			created_time INTEGER NOT NULL,
			updated_time INTEGER,
			status INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS user_tunnel (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			tunnel_id INTEGER NOT NULL,
			speed_id INTEGER,
			num INTEGER NOT NULL,
			flow INTEGER NOT NULL,
			in_flow INTEGER NOT NULL DEFAULT 0,
			out_flow INTEGER NOT NULL DEFAULT 0,
			flow_reset_time INTEGER NOT NULL,
			exp_time INTEGER NOT NULL,
			status INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS vite_config (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name VARCHAR(200) NOT NULL UNIQUE,
			value VARCHAR(200) NOT NULL,
			time INTEGER NOT NULL
		)`,
		`INSERT OR IGNORE INTO user (id, user, pwd, role_id, exp_time, flow, in_flow, out_flow, flow_reset_time, num, created_time, updated_time, status)
			VALUES (1, 'admin_user', '3c85cdebade1c51cf64ca9f3c09d182d', 0, 2727251700000, 99999, 0, 0, 1, 99999, 1748914865000, 1754011744252, 1)`,
		`INSERT OR IGNORE INTO vite_config (id, name, value, time) VALUES (1, 'app_name', 'flux', 1755147963000)`,
	}
	for _, stmt := range stmts {
		if _, err := a.db.Exec(stmt); err != nil {
			return err
		}
	}
	_, _ = a.db.Exec(`ALTER TABLE node ADD COLUMN exp_time INTEGER NOT NULL DEFAULT 0`)
	_, _ = a.db.Exec(`ALTER TABLE forward ADD COLUMN flow INTEGER NOT NULL DEFAULT 0`)
	_, _ = a.db.Exec(`ALTER TABLE forward ADD COLUMN exp_time INTEGER NOT NULL DEFAULT 0`)
	return nil
}

func (a *App) handleCaptchaCheck(w http.ResponseWriter, r *http.Request) {
	ok(w, 0)
}

func (a *App) handleCaptchaGenerate(w http.ResponseWriter, r *http.Request) {
	ok(w, map[string]any{"id": "disabled", "enabled": false})
}

func (a *App) handleCaptchaVerify(w http.ResponseWriter, r *http.Request) {
	ok(w, map[string]any{"success": true})
}

func (a *App) handleOpenSubStore(w http.ResponseWriter, r *http.Request) {
	ok(w, map[string]any{})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, -1, "请求格式错误")
		return
	}
	row := a.db.QueryRow(`SELECT id,user,pwd,role_id,status FROM user WHERE user=?`, req.Username)
	var id int64
	var user, pwd string
	var roleID, status int
	if err := row.Scan(&id, &user, &pwd, &roleID, &status); err != nil {
		fail(w, -1, "账号或密码错误")
		return
	}
	if pwd != md5Hex(req.Password) {
		fail(w, -1, "账号或密码错误")
		return
	}
	if status == 0 {
		fail(w, -1, "账号被停用")
		return
	}
	token, err := a.signToken(id, roleID, user)
	if err != nil {
		fail(w, -1, "生成token失败")
		return
	}
	ok(w, map[string]any{
		"token":                 token,
		"name":                  user,
		"role_id":               roleID,
		"requirePasswordChange": req.Username == "admin_user" || req.Password == "admin_user",
	})
}

func (a *App) handleConfigList(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query(`SELECT name,value FROM vite_config`)
	if err != nil {
		fail(w, -1, err.Error())
		return
	}
	defer rows.Close()
	data := map[string]string{}
	for rows.Next() {
		var k, v string
		_ = rows.Scan(&k, &v)
		data[k] = v
	}
	ok(w, data)
}

func (a *App) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	name := strVal(m["name"])
	var id, ts int64
	var value string
	err := a.db.QueryRow(`SELECT id,value,time FROM vite_config WHERE name=?`, name).Scan(&id, &value, &ts)
	if err != nil {
		ok(w, nil)
		return
	}
	ok(w, map[string]any{"id": id, "name": name, "value": value, "time": ts})
}

func (a *App) handleConfigUpdate(w http.ResponseWriter, r *http.Request) {
	m, err := readMap(r)
	if err != nil {
		fail(w, -1, "请求格式错误")
		return
	}
	for k, v := range m {
		a.upsertConfig(k, strVal(v))
	}
	ok(w, nil)
}

func (a *App) handleConfigUpdateSingle(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	a.upsertConfig(strVal(m["name"]), strVal(m["value"]))
	ok(w, nil)
}

func (a *App) upsertConfig(name, value string) {
	if name == "" {
		return
	}
	_, _ = a.db.Exec(`INSERT INTO vite_config(name,value,time) VALUES(?,?,?)
		ON CONFLICT(name) DO UPDATE SET value=excluded.value,time=excluded.time`, name, value, nowMS())
}

func (a *App) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	name := strVal(m["user"])
	pwd := strVal(m["pwd"])
	if name == "" || pwd == "" {
		fail(w, -1, "用户名和密码不能为空")
		return
	}
	_, err := a.db.Exec(`INSERT INTO user(user,pwd,role_id,exp_time,flow,in_flow,out_flow,flow_reset_time,num,created_time,updated_time,status)
		VALUES(?,?,?,?,?,0,0,?,?,?,?,?)`,
		name, md5Hex(pwd), 1, intVal(m["expTime"], 0), intVal(m["flow"], 0),
		intVal(m["flowResetTime"], 0), intVal(m["num"], 0), nowMS(), nowMS(), intVal(m["status"], 1))
	if err != nil {
		fail(w, -1, "用户名已存在或数据无效")
		return
	}
	ok(w, nil)
}

func (a *App) handleUserList(w http.ResponseWriter, r *http.Request) {
	list, err := a.queryMaps(`SELECT * FROM user WHERE role_id<>0 ORDER BY id DESC`)
	if err != nil {
		fail(w, -1, err.Error())
		return
	}
	ok(w, list)
}

func (a *App) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	id := intVal(m["id"], 0)
	if id == 0 {
		fail(w, -1, "用户不存在")
		return
	}
	if strVal(m["pwd"]) != "" {
		_, _ = a.db.Exec(`UPDATE user SET user=?,pwd=?,exp_time=?,flow=?,flow_reset_time=?,num=?,status=?,updated_time=? WHERE id=? AND role_id<>0`,
			strVal(m["user"]), md5Hex(strVal(m["pwd"])), intVal(m["expTime"], 0), intVal(m["flow"], 0),
			intVal(m["flowResetTime"], 0), intVal(m["num"], 0), intVal(m["status"], 1), nowMS(), id)
	} else {
		_, _ = a.db.Exec(`UPDATE user SET user=?,exp_time=?,flow=?,flow_reset_time=?,num=?,status=?,updated_time=? WHERE id=? AND role_id<>0`,
			strVal(m["user"]), intVal(m["expTime"], 0), intVal(m["flow"], 0),
			intVal(m["flowResetTime"], 0), intVal(m["num"], 0), intVal(m["status"], 1), nowMS(), id)
	}
	ok(w, nil)
}

func (a *App) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	id := intVal(m["id"], 0)
	if id == 1 {
		fail(w, -1, "不能删除管理员")
		return
	}
	forwards, _ := a.queryMaps(`SELECT id FROM forward WHERE user_id=?`, id)
	for _, f := range forwards {
		_ = a.deleteForwardByID(intVal(f["id"], 0), true)
	}
	_, _ = a.db.Exec(`DELETE FROM user_tunnel WHERE user_id=?`, id)
	_, _ = a.db.Exec(`DELETE FROM statistics_flow WHERE user_id=?`, id)
	_, _ = a.db.Exec(`DELETE FROM user WHERE id=? AND role_id<>0`, id)
	ok(w, nil)
}

func (a *App) handleUpdatePassword(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	m, _ := readMap(r)
	current := strVal(m["currentPassword"])
	newUser := strVal(m["newUsername"])
	newPwd := strVal(m["newPassword"])
	confirm := strVal(m["confirmPassword"])
	if newPwd == "" || newPwd != confirm {
		fail(w, -1, "新密码和确认密码不匹配")
		return
	}
	var oldHash string
	if err := a.db.QueryRow(`SELECT pwd FROM user WHERE id=?`, u.ID).Scan(&oldHash); err != nil || oldHash != md5Hex(current) {
		fail(w, -1, "当前密码错误")
		return
	}
	if newUser == "" {
		newUser = u.Name
	}
	_, err := a.db.Exec(`UPDATE user SET user=?,pwd=?,updated_time=? WHERE id=?`, newUser, md5Hex(newPwd), nowMS(), u.ID)
	if err != nil {
		fail(w, -1, "用户名已存在")
		return
	}
	ok(w, nil)
}

func (a *App) handleUserReset(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	id := intVal(m["id"], 0)
	if intVal(m["type"], 1) == 1 {
		_, _ = a.db.Exec(`UPDATE user SET in_flow=0,out_flow=0 WHERE id=?`, id)
	} else {
		_, _ = a.db.Exec(`UPDATE user_tunnel SET in_flow=0,out_flow=0 WHERE id=?`, id)
	}
	ok(w, nil)
}

func (a *App) handleUserPackage(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	userInfo, err := a.queryOne(`SELECT id,user,status,flow,in_flow,out_flow,num,exp_time,flow_reset_time,created_time,updated_time FROM user WHERE id=?`, u.ID)
	if err != nil {
		fail(w, -1, "用户不存在")
		return
	}
	tunnels, _ := a.queryMaps(`SELECT ut.*, t.name AS tunnel_name, t.flow AS tunnel_flow
		FROM user_tunnel ut LEFT JOIN tunnel t ON t.id=ut.tunnel_id WHERE ut.user_id=?`, u.ID)
	forwards, _ := a.queryMaps(`SELECT f.*, t.name AS tunnel_name FROM forward f LEFT JOIN tunnel t ON t.id=f.tunnel_id WHERE f.user_id=? ORDER BY f.inx ASC,id DESC`, u.ID)
	a.fillForwardEntrances(forwards)
	stats, _ := a.queryMaps(`SELECT * FROM statistics_flow WHERE user_id=? ORDER BY id DESC LIMIT 24`, u.ID)
	ok(w, map[string]any{
		"userInfo":          userInfo,
		"tunnelPermissions": tunnels,
		"forwards":          forwards,
		"statisticsFlows":   stats,
	})
}

func (a *App) handleNodeCreate(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	port := strVal(m["port"])
	if err := validatePortRange(port); err != nil {
		fail(w, -1, err.Error())
		return
	}
	secret := randomHex(16)
	_, err := a.db.Exec(`INSERT INTO node(name,secret,server_ip,port,interface_name,version,http,tls,socks,created_time,updated_time,status,tcp_listen_addr,udp_listen_addr,exp_time)
		VALUES(?,?,?,?,?,?,0,0,0,?,?,0,?,?,?)`,
		strVal(m["name"]), secret, strVal(m["serverIp"]), port, strVal(m["interfaceName"]), "",
		nowMS(), nowMS(), defaultListenAddr(strVal(m["tcpListenAddr"])), defaultListenAddr(strVal(m["udpListenAddr"])), 0)
	if err != nil {
		fail(w, -1, err.Error())
		return
	}
	ok(w, nil)
}

func (a *App) handleNodeList(w http.ResponseWriter, r *http.Request) {
	list, err := a.queryMaps(`SELECT * FROM node ORDER BY status DESC,id DESC`)
	if err != nil {
		fail(w, -1, err.Error())
		return
	}
	for _, n := range list {
		n["secret"] = nil
	}
	ok(w, list)
}

func (a *App) handleNodeUpdate(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	id := intVal(m["id"], 0)
	port := strVal(m["port"])
	if err := validatePortRange(port); err != nil {
		fail(w, -1, err.Error())
		return
	}
	node, err := a.queryOne(`SELECT * FROM node WHERE id=?`, id)
	if err != nil {
		fail(w, -1, "节点不存在")
		return
	}
	newHTTP, newTLS, newSOCKS := intVal(m["http"], intVal(node["http"], 0)), intVal(m["tls"], intVal(node["tls"], 0)), intVal(m["socks"], intVal(node["socks"], 0))
	if intVal(node["status"], 0) == 1 && (newHTTP != intVal(node["http"], 0) || newTLS != intVal(node["tls"], 0) || newSOCKS != intVal(node["socks"], 0)) {
		resp, err := a.sendAgentCommand(int64(id), "SetProtocol", map[string]any{"http": newHTTP, "tls": newTLS, "socks": newSOCKS})
		if err != nil || resp.Message != "OK" {
			fail(w, -1, commandError(resp, err))
			return
		}
	}
	_, _ = a.db.Exec(`UPDATE node SET name=?,server_ip=?,port=?,interface_name=?,http=?,tls=?,socks=?,updated_time=?,tcp_listen_addr=?,udp_listen_addr=?,exp_time=? WHERE id=?`,
		strVal(m["name"]), strVal(m["serverIp"]), port, strVal(m["interfaceName"]), newHTTP, newTLS, newSOCKS, nowMS(),
		defaultListenAddr(strVal(m["tcpListenAddr"])), defaultListenAddr(strVal(m["udpListenAddr"])), 0, id)
	ok(w, nil)
}

func (a *App) handleNodeDelete(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	id := intVal(m["id"], 0)
	tunnels, _ := a.queryMaps(`SELECT DISTINCT tunnel_id FROM chain_tunnel WHERE node_id=?`, id)
	for _, t := range tunnels {
		_ = a.deleteTunnelByID(intVal(t["tunnelId"], 0))
	}
	_, _ = a.db.Exec(`DELETE FROM node WHERE id=?`, id)
	a.closeNode(int64(id), websocket.CloseNormalClosure, "deleted")
	ok(w, nil)
}

func (a *App) handleNodeInstall(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	id := intVal(m["id"], 0)
	node, err := a.queryOne(`SELECT secret FROM node WHERE id=?`, id)
	if err != nil {
		fail(w, -1, "节点不存在")
		return
	}
	publicAddr := a.cfg.AgentPublicAddr
	if publicAddr == "" {
		if cfg, err := a.queryOne(`SELECT value FROM vite_config WHERE name='agent_addr'`); err == nil {
			publicAddr = strVal(cfg["value"])
		}
	}
	if publicAddr == "" {
		if cfg, err := a.queryOne(`SELECT value FROM vite_config WHERE name='ip'`); err == nil {
			publicAddr = strVal(cfg["value"])
		}
	}
	if publicAddr == "" {
		publicAddr = a.cfg.PublicAddr
	}
	if publicAddr == "" {
		fail(w, -1, "请先在网站配置中设置节点通信地址")
		return
	}
	url := a.cfg.AgentInstallURL
	if url == "" {
		url = "https://github.com/bqlpfy/flux-panel/releases/download/2.0.7-lite/install.sh"
	}
	releaseEnv := ""
	if a.cfg.AgentReleaseURL != "" {
		releaseEnv = "FLUX_AGENT_RELEASE_URL=" + shellQuote(a.cfg.AgentReleaseURL) + " "
	}
	cmd := fmt.Sprintf("curl -L %s -o ./install.sh && chmod +x ./install.sh && %s./install.sh -a %s -s %s",
		url, releaseEnv, shellQuote(processServerAddress(publicAddr)), shellQuote(strVal(node["secret"])))
	ok(w, cmd)
}

func (a *App) handleTunnelCreate(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	name := strVal(m["name"])
	if name == "" {
		fail(w, -1, "隧道名称不能为空")
		return
	}
	tType := intVal(m["type"], 1)
	if err := a.validateNodesAvailableFromPayload(m, tType); err != nil {
		fail(w, -1, err.Error())
		return
	}
	tx, err := a.db.Begin()
	if err != nil {
		fail(w, -1, err.Error())
		return
	}
	res, err := tx.Exec(`INSERT INTO tunnel(name,traffic_ratio,type,protocol,flow,created_time,updated_time,status,in_ip)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		name, floatVal(m["trafficRatio"], 1), tType, strDefault(strVal(m["protocol"]), "tls"), intVal(m["flow"], 1), nowMS(), nowMS(), 1, strVal(m["inIp"]))
	if err != nil {
		_ = tx.Rollback()
		fail(w, -1, err.Error())
		return
	}
	tunnelID, _ := res.LastInsertId()
	if err := a.insertChainTunnels(tx, tunnelID, m); err != nil {
		_ = tx.Rollback()
		fail(w, -1, err.Error())
		return
	}
	_ = tx.Commit()
	if strVal(m["inIp"]) == "" {
		a.refreshTunnelInIP(tunnelID)
	}
	if tType == 2 {
		if err := a.applyTunnelChain(tunnelID); err != nil {
			_ = a.deleteTunnelByID(int(tunnelID))
			fail(w, -1, err.Error())
			return
		}
	}
	ok(w, nil)
}

func (a *App) handleTunnelList(w http.ResponseWriter, r *http.Request) {
	tunnels, err := a.queryMaps(`SELECT * FROM tunnel ORDER BY id DESC`)
	if err != nil {
		fail(w, -1, err.Error())
		return
	}
	for _, t := range tunnels {
		id := intVal(t["id"], 0)
		chains, _ := a.queryMaps(`SELECT * FROM chain_tunnel WHERE tunnel_id=? ORDER BY chain_type ASC,inx ASC,id ASC`, id)
		var inNodes, outNodes []map[string]any
		groupMap := map[int][]map[string]any{}
		for _, c := range chains {
			switch intVal(c["chainType"], 0) {
			case 1:
				inNodes = append(inNodes, c)
			case 2:
				idx := intVal(c["inx"], 0)
				groupMap[idx] = append(groupMap[idx], c)
			case 3:
				outNodes = append(outNodes, c)
			}
		}
		var groups []any
		for i := 1; ; i++ {
			g, ok := groupMap[i]
			if !ok {
				break
			}
			groups = append(groups, g)
		}
		t["inNodeId"] = inNodes
		t["chainNodes"] = groups
		t["outNodeId"] = outNodes
	}
	ok(w, tunnels)
}

func (a *App) handleTunnelUpdate(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	id := intVal(m["id"], 0)
	_, _ = a.db.Exec(`UPDATE tunnel SET name=?,flow=?,traffic_ratio=?,in_ip=?,updated_time=? WHERE id=?`,
		strVal(m["name"]), intVal(m["flow"], 1), floatVal(m["trafficRatio"], 1), strVal(m["inIp"]), nowMS(), id)
	if strVal(m["inIp"]) == "" {
		a.refreshTunnelInIP(int64(id))
	}
	ok(w, nil)
}

func (a *App) handleTunnelDelete(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	if err := a.deleteTunnelByID(intVal(m["id"], 0)); err != nil {
		fail(w, -1, err.Error())
		return
	}
	ok(w, nil)
}

func (a *App) handleUserTunnelAssign(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	_, err := a.db.Exec(`INSERT INTO user_tunnel(user_id,tunnel_id,speed_id,num,flow,in_flow,out_flow,flow_reset_time,exp_time,status)
		VALUES(?,?,?,?,?,0,0,?,?,1)`,
		intVal(m["userId"], 0), intVal(m["tunnelId"], 0), nullableInt(m["speedId"]), intVal(m["num"], 0),
		intVal(m["flow"], 0), intVal(m["flowResetTime"], 0), intVal(m["expTime"], 0))
	if err != nil {
		fail(w, -1, err.Error())
		return
	}
	ok(w, nil)
}

func (a *App) handleUserTunnelList(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	rows, err := a.queryMaps(`SELECT ut.*, t.name AS tunnel_name, sl.name AS speed_name
		FROM user_tunnel ut
		LEFT JOIN tunnel t ON t.id=ut.tunnel_id
		LEFT JOIN speed_limit sl ON sl.id=ut.speed_id
		WHERE (?=0 OR ut.user_id=?)
		ORDER BY ut.id DESC`, intVal(m["userId"], 0), intVal(m["userId"], 0))
	if err != nil {
		fail(w, -1, err.Error())
		return
	}
	ok(w, rows)
}

func (a *App) handleUserTunnelRemove(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	id := intVal(m["id"], 0)
	ut, err := a.queryOne(`SELECT * FROM user_tunnel WHERE id=?`, id)
	if err == nil {
		forwards, _ := a.queryMaps(`SELECT id FROM forward WHERE user_id=? AND tunnel_id=?`, intVal(ut["userId"], 0), intVal(ut["tunnelId"], 0))
		for _, f := range forwards {
			_ = a.deleteForwardByID(intVal(f["id"], 0), true)
		}
	}
	_, _ = a.db.Exec(`DELETE FROM user_tunnel WHERE id=?`, id)
	ok(w, nil)
}

func (a *App) handleUserTunnelUpdate(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	id := intVal(m["id"], 0)
	_, _ = a.db.Exec(`UPDATE user_tunnel SET speed_id=?,num=?,flow=?,flow_reset_time=?,exp_time=?,status=? WHERE id=?`,
		nullableInt(m["speedId"]), intVal(m["num"], 0), intVal(m["flow"], 0),
		intVal(m["flowResetTime"], 0), intVal(m["expTime"], 0), intVal(m["status"], 1), id)
	ut, err := a.queryOne(`SELECT * FROM user_tunnel WHERE id=?`, id)
	if err == nil {
		forwards, _ := a.queryMaps(`SELECT id,name,remote_addr,strategy,user_id FROM forward WHERE user_id=? AND tunnel_id=?`, intVal(ut["userId"], 0), intVal(ut["tunnelId"], 0))
		for _, f := range forwards {
			_, _ = a.updateForwardServices(intVal(f["id"], 0))
		}
	}
	ok(w, nil)
}

func (a *App) handleUsableTunnels(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	var rows []map[string]any
	if u.RoleID == 0 {
		rows, _ = a.queryMaps(`SELECT * FROM tunnel WHERE status=1 ORDER BY id DESC`)
	} else {
		rows, _ = a.queryMaps(`SELECT t.* FROM tunnel t JOIN user_tunnel ut ON ut.tunnel_id=t.id WHERE ut.user_id=? AND t.status=1 AND ut.status=1`, u.ID)
	}
	ok(w, rows)
}

func (a *App) handleTunnelDiagnose(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	id := intVal(m["tunnelId"], 0)
	results := a.diagnoseTunnel(id, "")
	ok(w, map[string]any{"tunnelId": id, "results": results, "timestamp": nowMS()})
}

func (a *App) handleForwardCreate(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	m, _ := readMap(r)
	tunnelID := intVal(m["tunnelId"], 0)
	if err := a.checkForwardPermission(u, tunnelID, 0); err != nil {
		fail(w, -1, err.Error())
		return
	}
	tunnel, err := a.queryOne(`SELECT * FROM tunnel WHERE id=?`, tunnelID)
	if err != nil || intVal(tunnel["status"], 0) != 1 {
		fail(w, -1, "隧道不存在或已禁用")
		return
	}
	tx, _ := a.db.Begin()
	flow := intVal(m["flow"], 0)
	expTime := intVal(m["expTime"], 0)
	status := 1
	if expTime > 0 && expTime <= int(nowMS()) {
		status = 0
	}
	res, err := tx.Exec(`INSERT INTO forward(user_id,user_name,name,tunnel_id,remote_addr,strategy,flow,exp_time,in_flow,out_flow,created_time,updated_time,status,inx)
		VALUES(?,?,?,?,?,?,?,?,0,0,?,?,?,0)`, u.ID, u.Name, strVal(m["name"]), tunnelID, strVal(m["remoteAddr"]), strDefault(strVal(m["strategy"]), "fifo"), flow, expTime, nowMS(), nowMS(), status)
	if err != nil {
		_ = tx.Rollback()
		fail(w, -1, err.Error())
		return
	}
	id, _ := res.LastInsertId()
	ports, err := a.allocateForwardPorts(tx, tunnelID, intVal(m["inPort"], 0), id)
	if err != nil {
		_ = tx.Rollback()
		fail(w, -1, err.Error())
		return
	}
	for nodeID, port := range ports {
		_, _ = tx.Exec(`INSERT INTO forward_port(forward_id,node_id,port) VALUES(?,?,?)`, id, nodeID, port)
	}
	_ = tx.Commit()
	if status == 1 {
		if _, err := a.updateForwardServices(int(id)); err != nil {
			_ = a.deleteForwardByID(int(id), true)
			fail(w, -1, err.Error())
			return
		}
	}
	ok(w, nil)
}

func (a *App) handleForwardList(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	query := `SELECT f.*, t.name AS tunnel_name FROM forward f LEFT JOIN tunnel t ON t.id=f.tunnel_id`
	var args []any
	if u.RoleID != 0 {
		query += ` WHERE f.user_id=?`
		args = append(args, u.ID)
	}
	query += ` ORDER BY f.inx ASC,f.id DESC`
	rows, err := a.queryMaps(query, args...)
	if err != nil {
		fail(w, -1, err.Error())
		return
	}
	a.fillForwardEntrances(rows)
	ok(w, rows)
}

func (a *App) handleForwardUpdate(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	m, _ := readMap(r)
	id := intVal(m["id"], 0)
	fwd, err := a.queryOne(`SELECT * FROM forward WHERE id=?`, id)
	if err != nil || (u.RoleID != 0 && intVal(fwd["userId"], 0) != int(u.ID)) {
		fail(w, -1, "转发不存在")
		return
	}
	tunnelID := intVal(fwd["tunnelId"], 0)
	if err := a.checkForwardPermission(u, tunnelID, id); err != nil {
		fail(w, -1, err.Error())
		return
	}
	flow := intVal(m["flow"], intVal(fwd["flow"], 0))
	expTime := intVal(m["expTime"], intVal(fwd["expTime"], 0))
	status := 1
	if forwardLimitReached(flow, expTime, intVal(fwd["inFlow"], 0), intVal(fwd["outFlow"], 0)) {
		status = 0
	}
	if status == 0 && intVal(fwd["status"], 0) == 1 {
		_ = a.changeForwardState(id, 0)
	}
	_, _ = a.db.Exec(`UPDATE forward SET name=?,remote_addr=?,strategy=?,flow=?,exp_time=?,updated_time=?,status=? WHERE id=?`,
		strVal(m["name"]), strVal(m["remoteAddr"]), strDefault(strVal(m["strategy"]), "fifo"), flow, expTime, nowMS(), status, id)
	if inPort := intVal(m["inPort"], 0); inPort > 0 {
		if err := a.reallocateForwardPorts(id, tunnelID, inPort); err != nil {
			fail(w, -1, err.Error())
			return
		}
	}
	if status == 1 {
		if _, err := a.updateForwardServices(id); err != nil {
			fail(w, -1, err.Error())
			return
		}
		if intVal(fwd["status"], 0) == 0 {
			if err := a.changeForwardState(id, 1); err != nil {
				fail(w, -1, err.Error())
				return
			}
		}
	}
	ok(w, nil)
}

func (a *App) handleForwardDelete(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	if err := a.deleteForwardByID(intVal(m["id"], 0), true); err != nil {
		fail(w, -1, err.Error())
		return
	}
	ok(w, nil)
}

func (a *App) handleForwardForceDelete(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	if err := a.deleteForwardByID(intVal(m["id"], 0), false); err != nil {
		fail(w, -1, err.Error())
		return
	}
	ok(w, nil)
}

func (a *App) handleForwardPause(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	if err := a.changeForwardState(intVal(m["id"], 0), 0); err != nil {
		fail(w, -1, err.Error())
		return
	}
	ok(w, nil)
}

func (a *App) handleForwardResume(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	if err := a.changeForwardState(intVal(m["id"], 0), 1); err != nil {
		fail(w, -1, err.Error())
		return
	}
	ok(w, nil)
}

func (a *App) handleForwardDiagnose(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	id := intVal(m["forwardId"], intVal(m["id"], 0))
	f, err := a.queryOne(`SELECT * FROM forward WHERE id=?`, id)
	if err != nil {
		fail(w, -1, "转发不存在")
		return
	}
	results := a.diagnoseTunnel(intVal(f["tunnelId"], 0), strVal(f["remoteAddr"]))
	ok(w, map[string]any{"forwardId": id, "results": results, "timestamp": nowMS()})
}

func (a *App) handleForwardOrder(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	items, _ := m["forwards"].([]any)
	for _, it := range items {
		im, _ := it.(map[string]any)
		_, _ = a.db.Exec(`UPDATE forward SET inx=? WHERE id=?`, intVal(im["inx"], 0), intVal(im["id"], 0))
	}
	ok(w, nil)
}

func (a *App) handleSpeedLimitCreate(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	tunnel, err := a.queryOne(`SELECT name FROM tunnel WHERE id=?`, intVal(m["tunnelId"], 0))
	if err != nil {
		fail(w, -1, "隧道不存在")
		return
	}
	res, err := a.db.Exec(`INSERT INTO speed_limit(name,speed,tunnel_id,tunnel_name,created_time,updated_time,status) VALUES(?,?,?,?,?,?,1)`,
		strVal(m["name"]), intVal(m["speed"], 0), intVal(m["tunnelId"], 0), strVal(tunnel["name"]), nowMS(), nowMS())
	if err != nil {
		fail(w, -1, err.Error())
		return
	}
	id, _ := res.LastInsertId()
	if err := a.applyLimiter(id); err != nil {
		_, _ = a.db.Exec(`DELETE FROM speed_limit WHERE id=?`, id)
		fail(w, -1, err.Error())
		return
	}
	ok(w, nil)
}

func (a *App) handleSpeedLimitList(w http.ResponseWriter, r *http.Request) {
	rows, err := a.queryMaps(`SELECT * FROM speed_limit ORDER BY id DESC`)
	if err != nil {
		fail(w, -1, err.Error())
		return
	}
	ok(w, rows)
}

func (a *App) handleSpeedLimitUpdate(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	id := intVal(m["id"], 0)
	_, _ = a.db.Exec(`UPDATE speed_limit SET name=?,speed=?,updated_time=? WHERE id=?`, strVal(m["name"]), intVal(m["speed"], 0), nowMS(), id)
	if err := a.applyLimiter(int64(id)); err != nil {
		fail(w, -1, err.Error())
		return
	}
	ok(w, nil)
}

func (a *App) handleSpeedLimitDelete(w http.ResponseWriter, r *http.Request) {
	m, _ := readMap(r)
	id := intVal(m["id"], 0)
	count := a.count(`SELECT COUNT(*) FROM user_tunnel WHERE speed_id=?`, id)
	if count > 0 {
		fail(w, -1, "该限速规则还有用户在使用，请先取消分配")
		return
	}
	sl, err := a.queryOne(`SELECT * FROM speed_limit WHERE id=?`, id)
	if err == nil {
		nodes, _ := a.queryMaps(`SELECT DISTINCT node_id FROM chain_tunnel WHERE tunnel_id=?`, intVal(sl["tunnelId"], 0))
		for _, n := range nodes {
			_, _ = a.sendAgentCommand(int64(intVal(n["nodeId"], 0)), "DeleteLimiters", map[string]any{"limiter": strconv.Itoa(id)})
		}
	}
	_, _ = a.db.Exec(`DELETE FROM speed_limit WHERE id=?`, id)
	ok(w, nil)
}

func (a *App) handleFlowTest(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("test"))
}

func (a *App) handleFlowConfig(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("ok"))
}

func (a *App) handleFlowUpload(w http.ResponseWriter, r *http.Request) {
	secret := r.URL.Query().Get("secret")
	var nodeID int64
	if err := a.db.QueryRow(`SELECT id FROM node WHERE secret=?`, secret).Scan(&nodeID); err != nil {
		_, _ = w.Write([]byte("ok"))
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	body = a.decryptIfNeeded(body, secret)
	var items []struct {
		N string `json:"n"`
		U int64  `json:"u"`
		D int64  `json:"d"`
	}
	if err := json.Unmarshal(body, &items); err != nil {
		_, _ = w.Write([]byte("ok"))
		return
	}
	for _, item := range items {
		if item.N == "" || item.N == "web_api" {
			continue
		}
		a.processFlow(item.N, item.D, item.U)
	}
	_, _ = w.Write([]byte("ok"))
}

func (a *App) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	conn, err := a.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	typ := r.URL.Query().Get("type")
	if typ == "1" {
		a.handleNodeSocket(conn, r)
		return
	}
	a.handleAdminSocket(conn, r)
}

func (a *App) handleNodeSocket(conn *websocket.Conn, r *http.Request) {
	secret := r.URL.Query().Get("secret")
	node, err := a.queryOne(`SELECT * FROM node WHERE secret=?`, secret)
	if err != nil {
		_ = conn.Close()
		return
	}
	id := int64(intVal(node["id"], 0))

	a.mu.Lock()
	if old := a.nodes[id]; old != nil && old.Conn != nil {
		_ = old.Conn.Close()
	}
	ns := &NodeSession{ID: id, Secret: secret, Conn: conn, Pending: map[string]chan CommandResponse{}}
	a.nodes[id] = ns
	a.mu.Unlock()

	_, _ = a.db.Exec(`UPDATE node SET status=1,version=?,http=?,tls=?,socks=?,updated_time=? WHERE id=?`,
		r.URL.Query().Get("version"), qInt(r, "http"), qInt(r, "tls"), qInt(r, "socks"), nowMS(), id)
	a.broadcast(map[string]any{"id": id, "type": "status", "data": 1})

	defer func() {
		a.mu.Lock()
		if a.nodes[id] == ns {
			delete(a.nodes, id)
			_, _ = a.db.Exec(`UPDATE node SET status=0,updated_time=? WHERE id=?`, nowMS(), id)
			a.broadcast(map[string]any{"id": id, "type": "status", "data": 0})
		}
		a.mu.Unlock()
		_ = conn.Close()
	}()

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		msg = a.decryptIfNeeded(msg, secret)
		var probe map[string]any
		if err := json.Unmarshal(msg, &probe); err == nil {
			if requestID := strVal(probe["requestId"]); requestID != "" {
				var resp CommandResponse
				_ = json.Unmarshal(msg, &resp)
				ns.PendingMu.Lock()
				ch := ns.Pending[requestID]
				if ch != nil {
					delete(ns.Pending, requestID)
				}
				ns.PendingMu.Unlock()
				if ch != nil {
					ch <- resp
				}
				continue
			}
		}
		a.broadcast(map[string]any{"id": id, "type": "info", "data": string(msg)})
	}
}

func (a *App) handleAdminSocket(conn *websocket.Conn, r *http.Request) {
	token := r.URL.Query().Get("secret")
	if _, err := a.parseToken(token); err != nil {
		_ = conn.Close()
		return
	}
	a.mu.Lock()
	a.admins[conn] = true
	a.adminMux[conn] = &sync.Mutex{}
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.admins, conn)
		delete(a.adminMux, conn)
		a.mu.Unlock()
		_ = conn.Close()
	}()
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

func (a *App) broadcast(v any) {
	data, _ := json.Marshal(v)
	a.mu.RLock()
	var conns []*websocket.Conn
	for conn := range a.admins {
		conns = append(conns, conn)
	}
	a.mu.RUnlock()
	for _, conn := range conns {
		a.mu.RLock()
		mu := a.adminMux[conn]
		a.mu.RUnlock()
		if mu == nil {
			continue
		}
		mu.Lock()
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			_ = conn.Close()
		}
		mu.Unlock()
	}
}

func (a *App) sendAgentCommand(nodeID int64, typ string, data any) (CommandResponse, error) {
	a.mu.RLock()
	ns := a.nodes[nodeID]
	a.mu.RUnlock()
	if ns == nil || ns.Conn == nil {
		return CommandResponse{}, errors.New("节点不在线")
	}
	requestID := randomHex(16)
	ch := make(chan CommandResponse, 1)
	ns.PendingMu.Lock()
	ns.Pending[requestID] = ch
	ns.PendingMu.Unlock()
	payload := map[string]any{"type": typ, "data": data, "requestId": requestID}
	raw, _ := json.Marshal(payload)
	ns.WriteMu.Lock()
	err := ns.Conn.WriteMessage(websocket.TextMessage, raw)
	ns.WriteMu.Unlock()
	if err != nil {
		return CommandResponse{}, err
	}
	select {
	case resp := <-ch:
		if !resp.Success && resp.Message == "" {
			resp.Message = "节点执行失败"
		}
		return resp, nil
	case <-time.After(10 * time.Second):
		ns.PendingMu.Lock()
		delete(ns.Pending, requestID)
		ns.PendingMu.Unlock()
		return CommandResponse{}, errors.New("等待节点响应超时")
	}
}

func (a *App) decryptIfNeeded(data []byte, secret string) []byte {
	var wrapper encryptedMessage
	if err := json.Unmarshal(data, &wrapper); err != nil || !wrapper.Encrypted || wrapper.Data == "" {
		return data
	}
	plain, err := decryptAESGCM(secret, wrapper.Data)
	if err != nil {
		return data
	}
	return plain
}

func encryptAESGCM(secret string, data []byte) (string, error) {
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := append(nonce, gcm.Seal(nil, nonce, data, nil)...)
	return base64.StdEncoding.EncodeToString(out), nil
}

func decryptAESGCM(secret, encoded string) ([]byte, error) {
	key := sha256.Sum256([]byte(secret))
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("encrypted data too short")
	}
	return gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
}

func (a *App) queryMaps(query string, args ...any) ([]map[string]any, error) {
	rows, err := a.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := map[string]any{}
		for i, c := range cols {
			m[snakeToCamel(c)] = normalizeDBValue(vals[i])
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (a *App) queryOne(query string, args ...any) (map[string]any, error) {
	rows, err := a.queryMaps(query, args...)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, sql.ErrNoRows
	}
	return rows[0], nil
}

func (a *App) count(query string, args ...any) int {
	var n int
	_ = a.db.QueryRow(query, args...).Scan(&n)
	return n
}

func normalizeDBValue(v any) any {
	switch x := v.(type) {
	case []byte:
		return string(x)
	default:
		return x
	}
}

func snakeToCamel(s string) string {
	parts := strings.Split(s, "_")
	for i := 1; i < len(parts); i++ {
		if parts[i] == "" {
			continue
		}
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, "")
}

func strVal(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

func intVal(v any, fallback int) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case json.Number:
		i, err := x.Int64()
		if err == nil {
			return int(i)
		}
	case string:
		if strings.TrimSpace(x) == "" {
			return fallback
		}
		i, err := strconv.ParseInt(x, 10, 64)
		if err == nil {
			return int(i)
		}
	}
	return fallback
}

func floatVal(v any, fallback float64) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int64:
		return float64(x)
	case int:
		return float64(x)
	case json.Number:
		f, err := x.Float64()
		if err == nil {
			return f
		}
	case string:
		f, err := strconv.ParseFloat(x, 64)
		if err == nil {
			return f
		}
	}
	return fallback
}

func nullableInt(v any) any {
	if v == nil || strVal(v) == "" {
		return nil
	}
	i := intVal(v, 0)
	if i == 0 {
		return nil
	}
	return i
}

func strDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func defaultListenAddr(v string) string {
	if strings.TrimSpace(v) == "" {
		return "[::]"
	}
	return v
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func qInt(r *http.Request, key string) int {
	i, _ := strconv.Atoi(r.URL.Query().Get(key))
	return i
}

func shellQuote(s string) string {
	if strings.ContainsAny(s, " \t\r\n'\"") {
		return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
	}
	return s
}

func validatePortRange(port string) error {
	if strings.TrimSpace(port) == "" {
		return errors.New("可用端口不合法")
	}
	for _, part := range strings.Split(port, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return errors.New("可用端口不合法")
		}
		if strings.Contains(part, "-") {
			pair := strings.Split(part, "-")
			if len(pair) != 2 {
				return errors.New("可用端口不合法")
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(pair[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(pair[1]))
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
				return errors.New("可用端口不合法")
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return errors.New("可用端口不合法")
			}
		}
	}
	return nil
}

func parsePorts(input string) []int {
	seen := map[int]bool{}
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			pair := strings.Split(part, "-")
			start, _ := strconv.Atoi(strings.TrimSpace(pair[0]))
			end, _ := strconv.Atoi(strings.TrimSpace(pair[1]))
			for i := start; i <= end; i++ {
				seen[i] = true
			}
		} else if p, err := strconv.Atoi(part); err == nil {
			seen[p] = true
		}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func commandError(resp CommandResponse, err error) string {
	if err != nil {
		return err.Error()
	}
	if resp.Message != "" {
		return resp.Message
	}
	return "节点执行失败"
}
