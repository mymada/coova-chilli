# Custom HTML Templates

This directory contains the HTML templates used for the captive portal pages. You can customize the look and feel of your portal by editing these files.

## Configuration

To use a custom template directory, specify its path in your `config.yaml` file:

```yaml
templatedir: /path/to/your/templates
```

If `templatedir` is not set, the application will not be able to find the templates and will fail to start. Ensure this path is correct.

## Available Templates

*   `login.html`: The main login page presented to unauthenticated users.
*   `status.html`: The page shown to authenticated users displaying their session status.

## Template Data

### status.html

You can use the following variables within the `status.html` template. They will be automatically and safely replaced by the application:

*   `{{.Username}}`: The username of the authenticated user.
*   `{{.IPAddress}}`: The client's IP address.
*   `{{.MACAddress}}`: The client's MAC address.
*   `{{.StartTime}}`: The time the session started (formatted as RFC 1123).
*   `{{.SessionDuration}}`: The total duration of the current session (e.g., "1h2m3s").

**Security Note:** All data passed to the templates is automatically HTML-escaped to prevent Cross-Site Scripting (XSS) attacks.