import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional
from fastapi import BackgroundTasks
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.alert_history import AlertHistory
from app.models.attack_type import AttackType
from app.models.traffic_log import TrafficLog
from app.models.system_log import SystemLog
from app.core.config import settings

class AlertManagementService:
    def create_alert_with_history(
        self,
        db: Session,
        log_id: int,
        attack_type_id: int,
        prediction_id: Optional[int],
        severity: str,
        notes: Optional[str] = None,
        background_tasks: Optional[BackgroundTasks] = None
    ) -> Alert:
        """
        Creates a security alert record, logs the initial history trace,
        and registers a background email notification dispatch task.
        """
        # 1. Create the alert
        alert = Alert(
            log_id=log_id,
            attack_type_id=attack_type_id,
            prediction_id=prediction_id,
            severity=severity.upper(),
            status="UNRESOLVED",
            notes=notes
        )
        db.add(alert)
        db.flush()

        # 2. Log initial Alert History
        initial_history = AlertHistory(
            alert_id=alert.id,
            status="UNRESOLVED",
            notes=notes or "Alert initiated automatically by active ML detection engine.",
            changed_by="SYSTEM"
        )
        db.add(initial_history)
        db.flush()

        # 3. Schedule email notification via background tasks
        if background_tasks:
            background_tasks.add_task(self.dispatch_email_notification, db, alert.id)
        else:
            # Fallback inline execution
            try:
                self.dispatch_email_notification(db, alert.id)
            except Exception as e:
                print(f"[Alert Service] Inline email dispatch error: {e}")

        return alert

    def update_alert_status(
        self,
        db: Session,
        alert_id: int,
        status: str,
        notes: Optional[str] = None,
        changed_by: str = "SYSTEM"
    ) -> Alert:
        """
        Updates alert resolution status and saves a transition audit history record.
        """
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return None

        status_upper = status.upper()
        # Only log history if there's an actual change in status or notes
        if alert.status != status_upper or alert.notes != notes:
            alert.status = status_upper
            if notes is not None:
                alert.notes = notes

            # Create history record
            history = AlertHistory(
                alert_id=alert.id,
                status=status_upper,
                notes=notes or f"Alert status transitioned to {status_upper}.",
                changed_by=changed_by
            )
            db.add(alert)
            db.add(history)
            db.commit()
            db.refresh(alert)

        return alert

    def dispatch_email_notification(self, db: Session, alert_id: int):
        """
        Gathers details and sends a formatted alert email using SMTP.
        Logs status inside SystemLog.
        """
        # Fetch alert details
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            self._log_system_event(db, "WARNING", f"Email send cancelled. Alert ID {alert_id} not found.")
            return

        attack_name = alert.attack_type.name if alert.attack_type else "Unknown Threat"
        severity = alert.severity
        log = alert.traffic_log
        
        src_ip = log.src_ip if log else "N/A"
        src_port = log.src_port if log else "N/A"
        dst_ip = log.dst_ip if log else "N/A"
        dst_port = log.dst_port if log else "N/A"
        protocol = log.protocol if log else "N/A"
        time_str = alert.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")

        # HTML Email layout
        subject = f"[NIDS ALERT] [{severity}] Detected Intrusion: {attack_name}"
        html_content = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background-color: #0b0f19; color: #f3f4f6; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background-color: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 30px; border-left: 5px solid {'#ef4444' if severity == 'CRITICAL' else ('#f97316' if severity == 'HIGH' else '#f59e0b')};">
                    <h2 style="color: #ef4444; margin-top: 0;">⚠️ Security Threat Detected</h2>
                    <p>The AI-Powered NIDS has detected a potential network intrusion. Please review details below:</p>
                    
                    <table style="width: 100%; border-collapse: collapse; margin: 20px 0; color: #f3f4f6;">
                        <tr style="border-bottom: 1px solid #1f2937;">
                            <td style="padding: 10px 0; font-weight: bold; width: 150px;">Alert ID:</td>
                            <td style="padding: 10px 0;">{alert.id}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid #1f2937;">
                            <td style="padding: 10px 0; font-weight: bold;">Attack Class:</td>
                            <td style="padding: 10px 0; color: #f97316; font-weight: bold;">{attack_name}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid #1f2937;">
                            <td style="padding: 10px 0; font-weight: bold;">Severity Level:</td>
                            <td style="padding: 10px 0;"><span style="background-color: #7f1d1d; color: #fca5a5; padding: 2px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold;">{severity}</span></td>
                        </tr>
                        <tr style="border-bottom: 1px solid #1f2937;">
                            <td style="padding: 10px 0; font-weight: bold;">Source:</td>
                            <td style="padding: 10px 0; font-family: monospace;">{src_ip}:{src_port}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid #1f2937;">
                            <td style="padding: 10px 0; font-weight: bold;">Destination:</td>
                            <td style="padding: 10px 0; font-family: monospace;">{dst_ip}:{dst_port}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid #1f2937;">
                            <td style="padding: 10px 0; font-weight: bold;">Protocol:</td>
                            <td style="padding: 10px 0;">{protocol}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid #1f2937;">
                            <td style="padding: 10px 0; font-weight: bold;">Detected Time:</td>
                            <td style="padding: 10px 0;">{time_str}</td>
                        </tr>
                    </table>
                    
                    <p style="margin-bottom: 0;">Access the dashboard immediately to resolve active alerts or configure blocking rules.</p>
                </div>
            </body>
        </html>
        """

        # Initialize email message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM_EMAIL
        msg["To"] = settings.SMTP_TO_EMAIL
        msg.attach(MIMEText(html_content, "html"))

        # Skip SMTP execution if no host is set
        if not settings.SMTP_HOST:
            self._log_system_event(db, "INFO", f"Skipping email alert dispatch. SMTP_HOST not configured. Alert ID: {alert.id}")
            return

        try:
            # Handle sending
            if settings.SMTP_HOST == "localhost" or settings.SMTP_PORT == 1025:
                # Local mock SMTP or non-TLS direct dispatch for local debugging
                server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=3)
                server.sendmail(settings.SMTP_FROM_EMAIL, [settings.SMTP_TO_EMAIL], msg.as_string())
                server.quit()
            else:
                # Standard production-ready TLS dispatch
                server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=5)
                if settings.SMTP_TLS:
                    server.starttls()
                if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                server.sendmail(settings.SMTP_FROM_EMAIL, [settings.SMTP_TO_EMAIL], msg.as_string())
                server.quit()
                
            self._log_system_event(db, "INFO", f"Successfully dispatched alert email notification for Alert ID: {alert.id}")
            print(f"[Alert Service] Emailed alert {alert.id} to {settings.SMTP_TO_EMAIL}.")
        except Exception as e:
            # Fail silently to avoid blocking requests, log to SystemLog database instead
            error_msg = f"SMTP fail dispatching notification email for alert {alert.id}: {str(e)}"
            self._log_system_event(db, "ERROR", error_msg)
            print(f"[Alert Service] SMTP Error: {error_msg}")

    def _log_system_event(self, db: Session, level: str, message: str):
        try:
            sys_log = SystemLog(
                module_name="AlertService",
                log_level=level,
                message=message
            )
            db.add(sys_log)
            db.commit()
        except Exception as e:
            print(f"[Alert Service] Database error logging system event: {e}")

# Global Alert Management singleton instance
alert_service = AlertManagementService()
