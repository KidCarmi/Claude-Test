package main

// store_roster.go — the FE-6A.0 Administrators roster transaction
// (FE-V37): every admin-API mutation of the ui_users.json roster commits
// PERSIST-BEFORE-PUBLISH under ONE mutation lock, fenced on the server-
// minted roster revision, with the last-admin guard decided against the
// candidate inside that lock. A persistence failure leaves the in-memory
// roster, the legacy mirror, the sessions and the revision untouched (R10,
// R11, R12, R13).

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

var (
	errRosterLastAdmin     = errors.New("cannot demote or delete the last admin user")
	errRosterUserExists    = errors.New("user already exists")
	errRosterNotFound      = errors.New("user not found")
	errRosterPersistFailed = errors.New("persisting the admin roster failed; no change was applied")
)

// rosterStaleError carries the authoritative roster revision (409 stale).
type rosterStaleError struct{ Current int64 }

func (e *rosterStaleError) Error() string {
	return fmt.Sprintf("stale roster revision (current %d)", e.Current)
}

// RosterRevision returns the current fencing token (floor 1 so a caller can
// always echo a positive value).
func (c *Config) RosterRevision() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.rosterRevision <= 0 {
		return 1
	}
	return c.rosterRevision
}

// commitRoster runs one roster transaction: snapshot the live roster into
// a candidate copy → (optional) revision fence → mutate the candidate →
// persist the candidate with the NEXT revision → only then publish it
// (roster, revision, legacy mirror, auth cache). expectedRev == nil skips
// the fence (self-service paths); a non-nil mismatch is *rosterStaleError.
// Returns the revision now in force.
func (c *Config) commitRoster(expectedRev *int64, mutate func(next map[string]*uiAdminUser) error) (int64, error) {
	c.saveUIUsersMu.Lock()
	defer c.saveUIUsersMu.Unlock()

	c.mu.RLock()
	path := c.uiUsersFile
	outcome := c.defaultAuthOutcome
	if outcome == "" {
		outcome = OutcomeDefault
	}
	current := c.rosterRevision
	if current <= 0 {
		current = 1
	}
	next := make(map[string]*uiAdminUser, len(c.uiUsers)+1)
	for name, u := range c.uiUsers {
		if u == nil {
			continue
		}
		cp := *u
		cp.passHash = append([]byte(nil), u.passHash...)
		cp.backupCodes = append([]string(nil), u.backupCodes...)
		next[name] = &cp
	}
	c.mu.RUnlock()

	if expectedRev != nil && *expectedRev != current {
		return current, &rosterStaleError{Current: current}
	}
	if err := mutate(next); err != nil {
		return current, err
	}
	nextRev := current + 1
	if path != "" {
		if err := writeRosterEnvelope(path, rosterEnvelope(next, string(outcome), nextRev)); err != nil {
			return current, fmt.Errorf("%w: %v", errRosterPersistFailed, err)
		}
	}
	c.mu.Lock()
	c.uiUsers = next
	c.rosterRevision = nextRev
	c.authRevision++
	c.cache.clear()
	c.syncLegacyMirrorLocked()
	c.mu.Unlock()
	return nextRev, nil
}

// CreateUIUser creates a NEW roster entry (409 user_exists when present —
// create is never an upsert, R13).
func (c *Config) CreateUIUser(username, password string, role UIRole) (int64, error) {
	if err := validatePasswordComplexity(password); err != nil {
		return 0, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}
	return c.commitRoster(nil, func(next map[string]*uiAdminUser) error {
		if next[username] != nil {
			return errRosterUserExists
		}
		return applyRosterSet(next, username, hash, role)
	})
}

// rosterUpdate reports what a fenced update changed.
type rosterUpdate struct {
	Revision        int64
	RoleChanged     bool
	PasswordChanged bool
	PreviousRole    UIRole
}

// UpdateUIUser replaces the role and/or password of an EXISTING user under
// the roster fence. password "" keeps the credential; role "" keeps the
// role. TOTP enrollment is preserved; demoting the last admin is refused.
func (c *Config) UpdateUIUser(username, password string, role UIRole, expectedRev int64) (rosterUpdate, error) {
	var hash []byte
	if password != "" {
		if err := validatePasswordComplexity(password); err != nil {
			return rosterUpdate{}, err
		}
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return rosterUpdate{}, err
		}
		hash = h
	}
	var out rosterUpdate
	rev, err := c.commitRoster(&expectedRev, func(next map[string]*uiAdminUser) error {
		existing := next[username]
		if existing == nil {
			return errRosterNotFound
		}
		out.PreviousRole = existing.role
		target := existing.role
		if role != "" {
			target = role
		}
		out.RoleChanged = target != existing.role
		out.PasswordChanged = hash != nil
		return applyRosterSet(next, username, hash, target)
	})
	out.Revision = rev
	return out, err
}

// DeleteUIUserFenced removes a user under the roster fence (404 not_found
// when absent, 409 last_admin).
func (c *Config) DeleteUIUserFenced(username string, expectedRev int64) (int64, error) {
	return c.commitRoster(&expectedRev, func(next map[string]*uiAdminUser) error {
		if next[username] == nil {
			return errRosterNotFound
		}
		return applyRosterDelete(next, username)
	})
}

// ChangeUIUserPassword is the self-service credential replacement (the
// caller verified the current password): unfenced, role and TOTP untouched,
// persist-before-publish.
func (c *Config) ChangeUIUserPassword(username, password string) (int64, error) {
	if err := validatePasswordComplexity(password); err != nil {
		return 0, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}
	return c.commitRoster(nil, func(next map[string]*uiAdminUser) error {
		existing := next[username]
		if existing == nil {
			return errRosterNotFound
		}
		existing.passHash = hash
		return nil
	})
}

// uiUsersFilePath returns the configured roster path ("" = in-memory).
func (c *Config) uiUsersFilePath() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.uiUsersFile
}
