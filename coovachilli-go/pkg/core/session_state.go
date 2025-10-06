package core

import (
	"fmt"
	"sync"
)

// SessionState represents the state of a session in the state machine
type SessionState string

const (
	// SessionStateNew - Session just created, no DHCP lease yet
	SessionStateNew SessionState = "new"

	// SessionStateDHCPPending - DHCP DISCOVER sent, waiting for OFFER/ACK
	SessionStateDHCPPending SessionState = "dhcp_pending"

	// SessionStateDHCPBound - DHCP lease obtained, IP assigned
	SessionStateDHCPBound SessionState = "dhcp_bound"

	// SessionStateAuthPending - Sent to RADIUS for authentication
	SessionStateAuthPending SessionState = "auth_pending"

	// SessionStateAuthenticated - Successfully authenticated, firewall rules applied
	SessionStateAuthenticated SessionState = "authenticated"

	// SessionStateDisconnecting - Disconnect in progress
	SessionStateDisconnecting SessionState = "disconnecting"

	// SessionStateClosed - Session fully closed
	SessionStateClosed SessionState = "closed"
)

// SessionStateMachine manages state transitions for sessions
type SessionStateMachine struct {
	mu              sync.RWMutex
	currentState    SessionState
	allowedTransitions map[SessionState][]SessionState
}

// NewSessionStateMachine creates a new state machine
func NewSessionStateMachine() *SessionStateMachine {
	return &SessionStateMachine{
		currentState: SessionStateNew,
		allowedTransitions: map[SessionState][]SessionState{
			SessionStateNew: {
				SessionStateDHCPPending,
				SessionStateClosed, // Can close without DHCP
			},
			SessionStateDHCPPending: {
				SessionStateDHCPBound,
				SessionStateClosed, // DHCP failed
			},
			SessionStateDHCPBound: {
				SessionStateAuthPending,
				SessionStateClosed, // Closed before auth
			},
			SessionStateAuthPending: {
				SessionStateAuthenticated,
				SessionStateDHCPBound, // Auth failed, back to bound
				SessionStateClosed,    // Closed during auth
			},
			SessionStateAuthenticated: {
				SessionStateDHCPBound,        // Reauthentication needed
				SessionStateDisconnecting,
			},
			SessionStateDisconnecting: {
				SessionStateClosed,
			},
			SessionStateClosed: {
				// Terminal state, no transitions
			},
		},
	}
}

// GetState returns the current state
func (sm *SessionStateMachine) GetState() SessionState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.currentState
}

// CanTransitionTo checks if transition is allowed
func (sm *SessionStateMachine) CanTransitionTo(newState SessionState) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	allowed, exists := sm.allowedTransitions[sm.currentState]
	if !exists {
		return false
	}

	for _, s := range allowed {
		if s == newState {
			return true
		}
	}
	return false
}

// TransitionTo attempts to transition to a new state
func (sm *SessionStateMachine) TransitionTo(newState SessionState) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	allowed, exists := sm.allowedTransitions[sm.currentState]
	if !exists {
		return fmt.Errorf("no transitions defined from state %s", sm.currentState)
	}

	canTransition := false
	for _, s := range allowed {
		if s == newState {
			canTransition = true
			break
		}
	}

	if !canTransition {
		return fmt.Errorf("invalid transition from %s to %s", sm.currentState, newState)
	}

	sm.currentState = newState
	return nil
}

// ForceState forces a state (use with caution, bypasses validation)
func (sm *SessionStateMachine) ForceState(newState SessionState) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.currentState = newState
}

// IsTerminal checks if current state is terminal
func (sm *SessionStateMachine) IsTerminal() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.currentState == SessionStateClosed
}

// IsAuthenticated checks if session is in authenticated state
func (sm *SessionStateMachine) IsAuthenticated() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.currentState == SessionStateAuthenticated
}
