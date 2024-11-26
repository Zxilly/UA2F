import systemd.journal
from typing import List, Dict, Optional

class SystemdLogReader:
    def __init__(self):
        self.journal = systemd.journal.Reader()

    def _format_timestamp(self, timestamp):
        """
        格式化时间戳

        :param timestamp: systemd日志时间戳
        :return: 格式化的日期时间字符串
        """
        return timestamp.strftime('%Y-%m-%d %H:%M:%S') if timestamp else None

    def read_logs(
            self,
            count: int = 50,
            priority: Optional[int] = None,
            match_unit: Optional[str] = None,
            match_identifier: Optional[str] = None
    ) -> List[Dict]:
        logs = []

        # 配置日志过滤条件
        if priority is not None:
            self.journal.add_match(PRIORITY=priority)

        if match_unit:
            self.journal.add_match(_SYSTEMD_UNIT=match_unit)

        if match_identifier:
            self.journal.add_match(SYSLOG_IDENTIFIER=match_identifier)

        # 按时间倒序排序
        self.journal.seek_tail()
        self.journal.get_previous()

        # 读取日志
        for entry in self.journal:
            log_entry = {
                'timestamp': self._format_timestamp(entry.get('__REALTIME_TIMESTAMP')),
                'message': entry.get('MESSAGE', ''),
                'unit': entry.get('_SYSTEMD_UNIT', ''),
                'process_name': entry.get('SYSLOG_IDENTIFIER', ''),
                'pid': entry.get('_PID', ''),
                'hostname': entry.get('_HOSTNAME', ''),
                'priority_level': entry.get('PRIORITY', '')
            }

            logs.append(log_entry)

            if len(logs) >= count:
                break

        return logs

    def filter_logs_by_keyword(
            self,
            logs: List[Dict],
            keyword: str
    ) -> List[Dict]:
        return [
            log for log in logs
            if keyword.lower() in log['message'].lower()
        ]
