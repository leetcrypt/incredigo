package browserrot

import (
	"strings"

	"incredigo/internal/rotate"
)

// Curated recipes for self-hosted software whose markup is stable and known. These
// seed the Tier-1 selector table; on a first real run any miss is repaired by the
// Tier-2 self-heal (Healer) and re-persisted (recipes.go), so a slightly-off seed
// self-corrects rather than failing permanently. A recipe stays ProofUnproven until
// it has actually driven a rotation on that host — same proof-as-data discipline as
// the API drivers (rotate/proofs.go); only then does it promote to LIVE-REAL.

// GiteaSite builds a change-password recipe for a Gitea instance. baseURL is the
// scheme+host (e.g. "https://gitea.example.com"), username the account login.
//
// Gitea reaches the change-password controls only inside an authenticated session
// (/user/settings/account 302s to /user/login otherwise), so LoginBeforeChange is on.
// The password form on the account page carries old_password / password / retype; the
// result renders in a flash message. Every selector here was VERIFIED against a live
// Gitea instance on 2026-07-21 (login, the three change fields, and the submit button)
// during the M-B4 live-fire; other instances/versions may drift, and self-heal will
// rewrite any that do. The SuccessText markers are the one part self-heal cannot fix
// (they are content, not selectors): a wrong marker only makes Rotate fail SAFE (old
// secret kept, human flagged), never a silent bad rotation.
func GiteaSite(baseURL, username string) Site {
	base := strings.TrimRight(baseURL, "/")
	return Site{
		Host:      strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://"),
		ChangeURL: base + "/user/settings/account",
		Form: Form{
			CurrentSel: "#old_password",
			NewSel:     "#password",
			ConfirmSel: "#retype",
			// Gitea's "Update Password" button carries NO type=submit ATTRIBUTE — it is
			// a bare <button> whose DOM .type property defaults to "submit". A CSS
			// [type=submit] matches the attribute, not the property, so it MISSES here
			// (confirmed live 2026-07-21). Select the account-password form's only
			// button instead; the page has exactly one form posting to this action.
			SubmitSel:   "form[action$='/user/settings/account'] button",
			SuccessSel:  ".ui.positive.message, .flash-success",
			SuccessText: "has been updated",
		},
		Login: Login{
			URL:     base + "/user/login",
			UserSel: "#user_name",
			PassSel: "#password",
			// Gitea's sign-in button is <button class="ui primary button"> with NO
			// type=submit attribute (confirmed by read-only inspection of a live
			// instance 2026-07-20) — it submits as the form's only button. The mobile
			// #navbar-expand-toggle button lacks "primary", so this stays unambiguous.
			SubmitSel: ".ui.primary.button",
			// Post-login, Gitea lands on the dashboard. The sign-out control's text is a
			// stable "logged in" marker across themes; confirm on first run.
			SuccessSel:  "body",
			SuccessText: username,
		},
		LoginBeforeChange: true,
		// LIVE-REAL: this recipe drove a real password rotation of a self-owned Gitea
		// account (trill-technician @ 100.117.177.50:3030) on 2026-07-21 via
		// lab/rung4-gitea-browser (M-B4) — backup-gated, verified by API re-auth. Same
		// proof-as-data discipline as the API drivers (rotate/proofs.go): proven at the
		// mechanism level against a real instance, not a blanket "works on every Gitea".
		Proof: rotate.ProofLiveReal,
	}
}
