"""Security Alerts backward compatibility wrapper."""
from dashboard.pages.security_alerts import render_security_alerts

def render_alerts_page(repository):
    render_security_alerts(repository)
