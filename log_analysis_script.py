import re
import csv


class LogAnalysis:
    """
    A class to analyze log files, extract key metrics, and generate reports.
    """

    def __init__(self, file_path="sample.log", output_file="log_analysis_results.csv"):
        """
        Initialize the LogAnalysis class with file paths and patterns.
        :param file_path: Path to the log file.
        :param output_file: Path for the output CSV file.
        """
        self.file_path = file_path
        self.output_file = output_file
        self.data_pattern = (
            r'(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)\s-\s-\s\[[^\]]+\]\s"([A-Z]+)\s([^\s]+)\sHTTP/[^\"]+"\s([1-5][0-9]{2})'
        )
        self.ip_extraction = None
        self.endpoints = None
        self.suspicious_activity = None

    def read_file(self):
        """
        Reads the log file and returns its content as a list of lines.
        :return: List of log lines.
        """
        with open(self.file_path, 'r') as log_file:
            return log_file.readlines()

    def data_extraction(self, content):
        """
        Extracts data from log content using regex and organizes it by IP address.
        :param content: Raw log content as a string.
        """
        data_template = {}

        # Extract data matching the pattern
        logs = re.findall(self.data_pattern, str(content))
        for log in logs:
            ip, method, endpoint, status_code = log

            if ip not in data_template:
                # Initialize data structure for new IP
                data_template[ip] = {
                    "requests": [],
                    "endpoints": [],
                    "status_codes": [],
                    "request_count": 0,
                    "failed_logins": []
                }

            # Populate the data structure
            data_template[ip]["requests"].append(f"{endpoint} - {status_code}")
            data_template[ip]["endpoints"].append(endpoint)
            data_template[ip]["status_codes"].append(status_code)
            data_template[ip]["request_count"] += 1
            if status_code == "401":  # Failed login attempts
                data_template[ip]["failed_logins"].append(endpoint)

        self.ip_extraction = data_template

    def endpoint_access(self):
        """
        Calculates access counts for each endpoint across all IPs.
        """
        if not self.ip_extraction:
            return "No data is extracted"

        end_points = {}
        for ip_data in self.ip_extraction.values():
            for endpoint in ip_data["endpoints"]:
                end_points[endpoint] = end_points.get(endpoint, 0) + 1

        self.endpoints = end_points

    def request_count_per_ip(self):
        """
        Returns the request count per IP, sorted by count in descending order.
        :return: Dictionary of IP addresses and their request counts.
        """
        if self.ip_extraction is None:
            content = self.read_file()
            self.data_extraction(content)

        # Sort by request count
        sorted_data = sorted(self.ip_extraction.items(), key=lambda x: x[1]["request_count"], reverse=True)
        return {ip: data["request_count"] for ip, data in sorted_data}

    def frequent_access_endpoint(self):
        """
        Returns the most frequently accessed endpoints, sorted by access count.
        :return: Dictionary of endpoints and their access counts.
        """
        if self.endpoints is None:
            self.endpoint_access()

        # Sort by access count
        return dict(sorted(self.endpoints.items(), key=lambda x: x[1], reverse=True))

    def detect_suspicious_activity(self, threshold=10):
        """
        Detects suspicious activity based on the number of failed login attempts.
        :param threshold: Minimum number of failed attempts to flag as suspicious.
        :return: Dictionary of suspicious IPs and their failed login counts.
        """
        if self.ip_extraction is None:
            content = self.read_file()
            self.data_extraction(content)

        output = {}
        for ip, data in self.ip_extraction.items():
            failed_login_count = len(data["failed_logins"])
            if failed_login_count >= threshold:
                output[ip] = failed_login_count

        self.suspicious_activity = output
        return output

    def output_csv(self):
        """
        Generates a CSV report with requests per IP, accessed endpoints, and suspicious activities.
        """
        with open(self.output_file, "w", newline="") as file:
            writer = csv.writer(file)

            # Write request counts per IP
            writer.writerow(["Requests per IP:"])
            for ip, count in self.request_count_per_ip().items():
                writer.writerow([ip, count])

            writer.writerow([])  # Blank line

            # Write most accessed endpoints
            writer.writerow(["Most Accessed Endpoints:"])
            for endpoint, count in self.frequent_access_endpoint().items():
                writer.writerow([endpoint, count])

            writer.writerow([])  # Blank line

            # Write suspicious activities
            writer.writerow(["Suspicious Activity:"])
            for ip, failed_count in self.detect_suspicious_activity().items():
                writer.writerow([ip, failed_count])

    def main(self):
        """
        Main function to process the log file and generate the CSV report.
        """
        self.output_csv()


if __name__ == "__main__":
    log_analysis = LogAnalysis(file_path="sample.log")
    log_analysis.main()
