package config

import (
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port                         int
	JWTSecret                    string
	JWTExpiresIn                 time.Duration
	MFAPendingExpiresIn          time.Duration
	CORSOrigins                  []string
	CSRFTrustedOrigins           []string
	CORSProtectionEnabled        bool
	CSRFProtectionEnabled        bool
	AllowedHosts                 []string
	PanelURL                     string
	PanelBackupDir               string
	LoginMaxAttempts             int
	LoginLockout                 time.Duration
	AgentSyncInterval            time.Duration
	OpenvpnInfoSyncInterval      time.Duration
	ClientSyncInterval           time.Duration
	ClientSessionFreshness       time.Duration
	ClientTrafficHistoryMinutes  int
	AgentMetricHistoryMinutes    int
	OpenvpnLogRetentionDays      int
	InitAdminUsername            string
	InitAdminPassword            string
	InitAdminEmail               string
}

func Load() Config {
	cors := parseCSVOptional(os.Getenv("CORS_ORIGIN"))
	csrf := parseCSVOptional(os.Getenv("CSRF_TRUSTED_ORIGINS"))
	if len(csrf) == 0 {
		csrf = cors
	}
	corsOn := envBool("CORS_PROTECTION_ENABLED", false)
	csrfOn := envBool("CSRF_PROTECTION_ENABLED", false)
	return Config{
		Port:                        envInt("PORT", 8080),
		JWTSecret:                   envString("JWT_SECRET", "dev_secret_change_me"),
		JWTExpiresIn:                envDuration("JWT_EXPIRES_IN", 15*time.Minute),
		MFAPendingExpiresIn:         envDuration("MFA_PENDING_TOKEN_EXPIRES_IN", 5*time.Minute),
		CORSOrigins:                 cors,
		CSRFTrustedOrigins:          csrf,
		CORSProtectionEnabled:       corsOn,
		CSRFProtectionEnabled:       csrfOn,
		AllowedHosts:                parseAllowedHosts(os.Getenv("ALLOWED_HOSTS"), cors),
		PanelURL:                    panelURL(cors),
		PanelBackupDir:              envString("PANEL_BACKUP_DIR", "data/panel-backups"),
		LoginMaxAttempts:            envInt("LOGIN_MAX_ATTEMPTS", 8),
		LoginLockout:                time.Duration(envInt("LOGIN_LOCKOUT_MINUTES", 15)) * time.Minute,
		AgentSyncInterval:           time.Duration(envInt("AGENT_SYNC_INTERVAL_MS", 2000)) * time.Millisecond,
		OpenvpnInfoSyncInterval:     time.Duration(envInt("OPENVPN_INFO_SYNC_INTERVAL_MS", 5000)) * time.Millisecond,
		ClientSyncInterval:          time.Duration(envInt("CLIENT_SYNC_INTERVAL_MS", 2000)) * time.Millisecond,
		ClientSessionFreshness:      time.Duration(envInt("CLIENT_SESSION_FRESHNESS_SECONDS", 60)) * time.Second,
		ClientTrafficHistoryMinutes: envInt("CLIENT_TRAFFIC_HISTORY_MINUTES", 15),
		AgentMetricHistoryMinutes:   envInt("AGENT_METRIC_HISTORY_MINUTES", 15),
		OpenvpnLogRetentionDays:     envInt("OPENVPN_LOG_RETENTION_DAYS", 10),
		InitAdminUsername:           strings.TrimSpace(os.Getenv("INIT_ADMIN_USERNAME")),
		InitAdminPassword:           os.Getenv("INIT_ADMIN_PASSWORD"),
		InitAdminEmail:              strings.TrimSpace(os.Getenv("INIT_ADMIN_EMAIL")),
	}
}

func parseCSVOptional(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return parseCSV(raw, "")
}

func parseCSV(raw, fallback string) []string {
	text := strings.TrimSpace(raw)
	if text == "" {
		text = fallback
	}
	var out []string
	for _, p := range strings.Split(text, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseAllowedHosts(raw string, cors []string) []string {
	text := strings.TrimSpace(raw)
	if text == "*" {
		return nil
	}
	if text != "" {
		var hosts []string
		for _, p := range strings.Split(text, ",") {
			p = strings.TrimSpace(strings.ToLower(p))
			if p != "" {
				hosts = append(hosts, p)
			}
		}
		if len(hosts) > 0 {
			return hosts
		}
	}
	seen := map[string]struct{}{}
	var out []string
	for _, o := range cors {
		u, err := url.Parse(o)
		if err != nil {
			continue
		}
		h := strings.ToLower(u.Host)
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}

func panelURL(cors []string) string {
	if u := strings.TrimRight(strings.TrimSpace(os.Getenv("PANEL_URL")), "/"); u != "" {
		return u
	}
	if len(cors) > 0 {
		return strings.TrimRight(cors[0], "/")
	}
	return "http://localhost:5173"
}

func envString(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envBool(k string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	if v == "" {
		return def
	}
	return v != "0" && v != "false" && v != "no" && v != "off"
}

func envDuration(k string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	return def
}
