package httpserver

import (
	"fmt"
	"html"
	"strings"
	"github.com/SUNET/vc/internal/registry/apiv1"
)

// Common CSS styles for all admin pages
const adminCSS = `
<style>
	* { box-sizing: border-box; margin: 0; padding: 0; }
	body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; }
	.container { max-width: 800px; margin: 0 auto; padding: 20px; }
	.card { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 24px; margin-bottom: 20px; }
	h1 { color: #333; margin-bottom: 20px; }
	h2 { color: #555; margin-bottom: 16px; font-size: 1.25rem; }
	.nav { background: #2563eb; padding: 16px 20px; margin-bottom: 20px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; }
	.nav a { color: white; text-decoration: none; margin-right: 20px; }
	.nav a:hover { text-decoration: underline; }
	.nav-title { color: white; font-weight: bold; font-size: 1.1rem; }
	.form-group { margin-bottom: 16px; }
	label { display: block; margin-bottom: 6px; color: #555; font-weight: 500; }
	input[type="text"], input[type="password"], input[type="number"], select { 
		width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px;
	}
	input:focus, select:focus { outline: none; border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37,99,235,0.1); }
	.btn { 
		padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500;
		transition: background 0.2s;
	}
	.btn-primary { background: #2563eb; color: white; }
	.btn-primary:hover { background: #1d4ed8; }
	.btn-danger { background: #dc2626; color: white; }
	.btn-danger:hover { background: #b91c1c; }
	.btn-success { background: #16a34a; color: white; }
	.btn-success:hover { background: #15803d; }
	.alert { padding: 12px 16px; border-radius: 6px; margin-bottom: 16px; }
	.alert-error { background: #fef2f2; border: 1px solid #fecaca; color: #dc2626; }
	.alert-success { background: #f0fdf4; border: 1px solid #bbf7d0; color: #16a34a; }
	.result-table { width: 100%; border-collapse: collapse; margin-top: 16px; }
	.result-table th, .result-table td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
	.result-table th { background: #f9fafb; font-weight: 600; color: #555; }
	.result-table tr:hover { background: #f9fafb; }
	.status-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 500; }
	.status-0 { background: #dcfce7; color: #16a34a; }
	.status-1 { background: #fef3c7; color: #d97706; }
	.status-2 { background: #fee2e2; color: #dc2626; }
	.status-other { background: #e5e7eb; color: #4b5563; }
	.inline-form { display: flex; gap: 10px; align-items: center; margin-top: 8px; }
	.inline-form input, .inline-form select { width: auto; }
	.login-container { display: flex; justify-content: center; align-items: center; min-height: 100vh; }
	.login-card { width: 100%; max-width: 400px; }
	.login-title { text-align: center; margin-bottom: 24px; }
</style>
`

// loginPageHTML generates the login page HTML
func loginPageHTML(errorMsg string) string {
	var errorHTML string
	if errorMsg != "" {
		errorHTML = fmt.Sprintf(`<div class="alert alert-error">%s</div>`, html.EscapeString(errorMsg))
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Registry Admin - Login</title>
	%s
</head>
<body>
	<div class="login-container">
		<div class="card login-card">
			<h1 class="login-title">Registry Admin</h1>
			%s
			<form method="POST" action="/admin/login">
				<div class="form-group">
					<label for="username">Username</label>
					<input type="text" id="username" name="username" required autofocus>
				</div>
				<div class="form-group">
					<label for="password">Password</label>
					<input type="password" id="password" name="password" required>
				</div>
				<button type="submit" class="btn btn-primary" style="width: 100%%;">Login</button>
			</form>
		</div>
	</div>
</body>
</html>`, adminCSS, errorHTML)
}

// dashboardPageHTML generates the dashboard page HTML
func dashboardPageHTML(username string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Registry Admin - Dashboard</title>
	%s
</head>
<body>
	%s
	<div class="container">
		<div class="card">
			<h1>Welcome, %s</h1>
			<p style="color: #666; margin-top: 8px;">Token Status List Registry Administration</p>
		</div>
		<div class="card">
			<h2>Quick Actions</h2>
			<p style="margin-bottom: 16px; color: #666;">Manage credential status entries in the Token Status List.</p>
			<a href="/admin/search" class="btn btn-primary">Search & Update Status</a>
		</div>
		<div class="card">
			<h2>Status Values</h2>
			<p style="color: #666; margin-bottom: 12px;">Standard status values per draft-ietf-oauth-status-list:</p>
			<ul style="list-style: none; padding: 0;">
				<li style="margin-bottom: 8px;"><span class="status-badge status-0">0 - VALID</span> Credential is valid</li>
				<li style="margin-bottom: 8px;"><span class="status-badge status-1">1 - INVALID</span> Credential is invalid</li>
				<li style="margin-bottom: 8px;"><span class="status-badge status-2">2 - SUSPENDED</span> Credential is suspended</li>
			</ul>
		</div>
	</div>
</body>
</html>`, adminCSS, navBarHTML(username), html.EscapeString(username))
}

// searchPageHTML generates the search page HTML
func searchPageHTML(errorMsg string, result *apiv1.SearchPersonReply, successMsg string, searchParams *apiv1.SearchPersonRequest) string {
	var alertHTML string
	if errorMsg != "" {
		alertHTML = fmt.Sprintf(`<div class="alert alert-error">%s</div>`, html.EscapeString(errorMsg))
	}
	if successMsg != "" {
		alertHTML = fmt.Sprintf(`<div class="alert alert-success">%s</div>`, html.EscapeString(successMsg))
	}

	var resultHTML string
	if result != nil && len(result.Results) > 0 {
		// Get search params for hidden fields
		searchFirstName := ""
		searchLastName := ""
		searchDateOfBirth := ""
		if searchParams != nil {
			searchFirstName = searchParams.FirstName
			searchLastName = searchParams.LastName
			searchDateOfBirth = searchParams.DateOfBirth
		}

		var rows strings.Builder
		for _, person := range result.Results {
			statusClass := fmt.Sprintf("status-%d", person.Status)
			if person.Status > 2 {
				statusClass = "status-other"
			}
			statusLabel := getStatusLabel(person.Status)

			rows.WriteString(fmt.Sprintf(`
				<tr>
					<td>%s</td>
					<td>%s</td>
					<td>%s</td>
					<td><span class="status-badge %s">%d - %s</span></td>
					<td>
						<form method="POST" action="/admin/status" class="inline-form">
							<input type="hidden" name="section" value="%d">
							<input type="hidden" name="index" value="%d">
							<input type="hidden" name="search_first_name" value="%s">
							<input type="hidden" name="search_last_name" value="%s">
							<input type="hidden" name="search_date_of_birth" value="%s">
							<select name="status" style="width: 120px;">
								<option value="0" %s>VALID</option>
								<option value="1" %s>INVALID</option>
								<option value="2" %s>SUSPENDED</option>
							</select>
							<button type="submit" class="btn btn-success" style="padding: 4px 8px;">Update</button>
						</form>
					</td>
				</tr>`,
				html.EscapeString(person.FirstName),
				html.EscapeString(person.LastName),
				html.EscapeString(person.DateOfBirth),
				statusClass, person.Status, statusLabel,
				person.Section, person.Index,
				html.EscapeString(searchFirstName), html.EscapeString(searchLastName), html.EscapeString(searchDateOfBirth),
				selected(person.Status == 0), selected(person.Status == 1), selected(person.Status == 2)))
		}

		resultHTML = fmt.Sprintf(`
		<div class="card">
			<h2>Search Results (%d found)</h2>
			<table class="result-table">
				<thead>
					<tr>
						<th>First Name</th>
						<th>Last Name</th>
						<th>Date of Birth</th>
						<th>Status</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
					%s
				</tbody>
			</table>
		</div>`, len(result.Results), rows.String())
	} else if result != nil {
		resultHTML = `<div class="card"><p>No results found.</p></div>`
	}

	// Get search values for form pre-fill
	searchFirstName := ""
	searchLastName := ""
	searchDateOfBirth := ""
	if searchParams != nil {
		searchFirstName = searchParams.FirstName
		searchLastName = searchParams.LastName
		searchDateOfBirth = searchParams.DateOfBirth
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Registry Admin - Search</title>
	%s
</head>
<body>
	%s
	<div class="container">
		<div class="card">
			<h1>Search Credential Subjects</h1>
			%s
			<form method="POST" action="/admin/search">
				<div style="display: flex; gap: 16px; flex-wrap: wrap;">
					<div class="form-group" style="flex: 1; min-width: 150px;">
						<label for="first_name">First Name</label>
						<input type="text" id="first_name" name="first_name" placeholder="e.g., John" value="%s">
					</div>
					<div class="form-group" style="flex: 1; min-width: 150px;">
						<label for="last_name">Last Name</label>
						<input type="text" id="last_name" name="last_name" placeholder="e.g., Doe" value="%s">
					</div>
					<div class="form-group" style="flex: 1; min-width: 150px;">
						<label for="date_of_birth">Date of Birth</label>
						<input type="text" id="date_of_birth" name="date_of_birth" placeholder="e.g., 1990-01-15" value="%s">
					</div>
				</div>
				<button type="submit" class="btn btn-primary">Search</button>
			</form>
		</div>
		%s
	</div>
</body>
</html>`, adminCSS, navBarHTML(""), alertHTML,
		html.EscapeString(searchFirstName), html.EscapeString(searchLastName), html.EscapeString(searchDateOfBirth),
		resultHTML)
}

// navBarHTML generates the navigation bar HTML
func navBarHTML(username string) string {
	logoutForm := ""
	if username != "" {
		logoutForm = fmt.Sprintf(`
			<div style="display: flex; align-items: center; gap: 16px;">
				<span style="color: rgba(255,255,255,0.8);">%s</span>
				<form method="POST" action="/admin/logout" style="margin: 0;">
					<button type="submit" class="btn btn-danger" style="padding: 6px 12px;">Logout</button>
				</form>
			</div>`, html.EscapeString(username))
	}

	return fmt.Sprintf(`
	<div class="container" style="padding-bottom: 0;">
		<div class="nav">
			<div>
				<span class="nav-title">Registry Admin</span>
				<a href="/admin/dashboard" style="margin-left: 24px;">Dashboard</a>
				<a href="/admin/search">Search</a>
			</div>
			%s
		</div>
	</div>`, logoutForm)
}

// Helper functions

func getStatusLabel(status uint8) string {
	switch status {
	case 0:
		return "VALID"
	case 1:
		return "INVALID"
	case 2:
		return "SUSPENDED"
	default:
		return "UNKNOWN"
	}
}

func selected(condition bool) string {
	if condition {
		return "selected"
	}
	return ""
}
