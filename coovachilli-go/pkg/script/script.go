package script

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"github.com/rs/zerolog"
)

// Runner executes external scripts with session-specific environment variables.
type Runner struct {
	logger zerolog.Logger
	cfg    *config.Config
}

// NewRunner creates a new script runner.
func NewRunner(logger zerolog.Logger, cfg *config.Config) *Runner {
	return &Runner{
		logger: logger.With().Str("component", "script").Logger(),
		cfg:    cfg,
	}
}

// setEnv adds a key-value pair to the environment string slice.
func setEnv(env []string, key string, value interface{}) []string {
	return append(env, fmt.Sprintf("%s=%v", key, value))
}

// setEnvStr adds a string key-value pair to the environment.
func setEnvStr(env []string, key, value string) []string {
	if value == "" {
		return env
	}
	return append(env, fmt.Sprintf("%s=%s", key, value))
}

// buildEnv creates the environment variable slice for the script execution.
func (r *Runner) buildEnv(session *core.Session, terminateCause int) []string {
	env := os.Environ()

	// Network and Interface Details
	env = setEnvStr(env, "DEV", r.cfg.TUNDev)
	env = setEnv(env, "NET", r.cfg.Net.IP.String())
	env = setEnv(env, "MASK", net.IP(r.cfg.Net.Mask).String())
	env = setEnv(env, "NAS_IP_ADDRESS", r.cfg.RadiusListen.String())
	env = setEnv(env, "ADDR", r.cfg.UAMListen.String())

	// Session and User Identifiers
	env = setEnvStr(env, "USER_NAME", session.Redir.Username)
	env = setEnv(env, "FRAMED_IP_ADDRESS", session.HisIP.String())
	env = setEnv(env, "CALLING_STATION_ID", strings.ReplaceAll(session.HisMAC.String(), ":", "-"))
	// TODO: Need to get Called-Station-Id (NAS MAC) from config
	// env = setEnv(env, "CALLED_STATION_ID", "00-00-00-00-00-00")
	env = setEnvStr(env, "ACCT_SESSION_ID", session.SessionID)
	env = setEnvStr(env, "NAS_ID", r.cfg.RadiusNASID)
	env = setEnv(env, "NAS_PORT_TYPE", 19)

	// RADIUS Attributes from Session
	env = setEnvStr(env, "FILTER_ID", session.SessionParams.FilterID)
	env = setEnvStr(env, "STATE", string(session.SessionParams.State))
	env = setEnvStr(env, "CLASS", string(session.SessionParams.Class))
	env = setEnv(env, "SESSION_TIMEOUT", session.SessionParams.SessionTimeout)
	env = setEnv(env, "IDLE_TIMEOUT", session.SessionParams.IdleTimeout)
	env = setEnv(env, "ACCT_INTERIM_INTERVAL", session.SessionParams.InterimInterval)

	// Bandwidth and Quota
	env = setEnv(env, "WISPR_BANDWIDTH_MAX_UP", session.SessionParams.BandwidthMaxUp)
	env = setEnv(env, "WISPR_BANDWIDTH_MAX_DOWN", session.SessionParams.BandwidthMaxDown)
	env = setEnv(env, "COOVACHILLI_MAX_INPUT_OCTETS", session.SessionParams.MaxInputOctets)
	env = setEnv(env, "COOVACHILLI_MAX_OUTPUT_OCTETS", session.SessionParams.MaxOutputOctets)
	env = setEnv(env, "COOVACHILLI_MAX_TOTAL_OCTETS", session.SessionParams.MaxTotalOctets)

	// Accounting Details
	env = setEnv(env, "INPUT_OCTETS", session.AcctInputOctets)
	env = setEnv(env, "OUTPUT_OCTETS", session.AcctOutputOctets)
	env = setEnv(env, "INPUT_PACKETS", session.AcctInputPackets)
	env = setEnv(env, "OUTPUT_PACKETS", session.AcctOutputPackets)

	// Timestamps
	sessionTime := uint32(0)
	idleTime := uint32(0)
	now := core.MonotonicTime()
	if !session.StartTime.IsZero() {
		sessionTime = now - session.StartTimeSec
	}
	if !session.LastActivityTime.IsZero() {
		idleTime = now - session.LastActivityTimeSec
	}
	env = setEnv(env, "SESSION_TIME", sessionTime)
	env = setEnv(env, "IDLE_TIME", idleTime)

	// Termination Cause (for condown script)
	if terminateCause > 0 {
		env = setEnv(env, "TERMINATE_CAUSE", terminateCause)
	}

	return env
}

// RunScript executes a script with the environment populated from the session.
func (r *Runner) RunScript(scriptPath string, session *core.Session, terminateCause int) {
	if scriptPath == "" {
		return
	}

	r.logger.Info().Str("script", scriptPath).Str("session", session.SessionID).Msg("Executing script")

	cmd := exec.Command(scriptPath)
	cmd.Env = r.buildEnv(session, terminateCause)

	go func() {
		output, err := cmd.CombinedOutput()
		if err != nil {
			r.logger.Error().Err(err).Str("script", scriptPath).Bytes("output", output).Msg("Script execution failed")
			return
		}
		r.logger.Debug().Str("script", scriptPath).Bytes("output", output).Msg("Script executed successfully")
	}()
}
