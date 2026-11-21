# Kvígindis .44 — Ubuntu 24.04, Furniture Help Site

**CVEs:** wp2shell (if WordPress) · PHP2Shell · Copy Fail · DirtyClone

- WP version: `grep wp_version wp-includes/version.php` (need 6.9.5 / 7.0.2 / 6.8.6). PHP: `php -v`.
- Block `/wp-json/batch/v1`, `?rest_route=/batch/v1`, `xmlrpc.php` in the web server.
- WP: rotate admins, delete unknown admins, new DB password + salts, `define('DISALLOW_FILE_EDIT', true);`, remove unused plugins/themes.
- Web root owned by root; writable only `wp-content/uploads`; no PHP execution in uploads.
- php.ini:
  ```
  session.upload_progress.enabled = Off
  disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec
  allow_url_include = Off
  expose_php = Off
  ```
  Check the site still works after `disable_functions`. Restart php-fpm/apache.
- Firewall: [../../linux/ufw_setup_debian.sh](../../linux/ufw_setup_debian.sh).
