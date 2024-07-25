"""
This plugin searches for SQL Server, Azure SQL and PostgreSQL connection strings.
"""
import re

from detect_secrets.plugins.base import RegexBasedDetector


class ConnectionStringDetector(RegexBasedDetector):
    """Scans for Connection Strings for SQL Server, Azure SQL and PostgreSQL."""
    secret_type = 'Connection String (SQL Server, Azure SQL, PostgreSQL)'

    denylist = [
        re.compile(r'(Server|Data Source|Address|Addr|Network Address)=.*', re.IGNORECASE),
        re.compile(r'(Initial Catalog|Database)=.*', re.IGNORECASE),
        re.compile(r'(User Id|Password|Integrated Security)=.*', re.IGNORECASE),
        re.compile(r'(host|serverr|port|dbname|database|user|user id|password=)=.*', re.IGNORECASE)
    ]