import re, csv

class Log_Analysis():
    
    def __init__(self,file_path="sample.log",output_file="log_analysis_results.csv") -> None:
        self.__FILE_PATH = file_path
        self.__OUTPUT_FILE = output_file
        self.__DATA_PATTERN = r'(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)\s-\s-\s\[[^\]]+\]\s"([A-Z]+)\s([^\s]+)\sHTTP/[^\"]+"\s([1-5][0-9]{2})'
        self.ip_extraction = None
        self.endpoints = None
        self.suspicious_activity = None

    def read_file(self):
        lines = None
        with open(self.__FILE_PATH,'r') as log_file:
            lines = log_file.readlines()
            return lines

    def data_extraction(self,content):
        data_template = {}

        data = re.findall(self.__DATA_PATTERN,str(content))
        for log in data:

            if not data_template.get(log[0]):
               data_template[log[0]] = {"body":[],"end_points":[],"status_code":[],"request_count":0,"failed_login":[]}
            data_template[log[0]]["body"].append(f"{log[2]} - {log[3]}")
            data_template[log[0]]["end_points"].append(f"{log[2]}")
            data_template[log[0]]["status_code"].append(f"{log[3]}")
            data_template[log[0]]["request_count"] = len(data_template[log[0]]["end_points"])
            if log[3] == "401":
                data_template[log[0]]["failed_login"].append(f"{log[2]}")

        self.ip_extraction = data_template

    def endpoint_access(self):
        extracted_data = self.ip_extraction if self.ip_extraction else None
        end_points = {}
        if extracted_data:
            for ip in extracted_data:
                for endpoint in extracted_data[ip]['end_points']:
                    if not end_points.get(endpoint):
                        end_points[endpoint] = 0
                    end_points[endpoint] += 1
            self.endpoints = end_points
            
        else:
            return "No data is extracted"


    def request_count_per_ip(self):
        if self.ip_extraction is None:
            content = self.read_file()
            self.data_extraction(content)
        sorted_data = sorted(self.ip_extraction.items(), key=lambda item: item[1]["request_count"],reverse=True)
        output = {"IP Address":"Request Count"}
        
        for log in sorted_data:
            output[log[0]] = log[1]['request_count']
        return output
        
    def frequent_access_endpoint(self):
        if self.endpoints is None:
            self.endpoint_access()
        sorted_endpoints = dict(sorted(self.endpoints.items(), key=lambda item: item[1],reverse=True))
        
        labels = {"Endpoint":"Access Count"}
        output = {**labels,**sorted_endpoints}
        return output
    
    def detect_suspicious_activity(self,threshold=10):
        data = self.ip_extraction
        output = {"IP Address":"Failed Login Count"}
        
        for data in data.items():
            if data[1]["failed_login"] and len(data[1]["failed_login"]) >= threshold:
                output[data[0]] = len(data[1]["failed_login"])
        self.suspicious_activity = output
        return output

    def output_csv(self):
        with open(self.__OUTPUT_FILE,"w",newline="") as file:
            writer = csv.writer(file)

            writer.writerow(["Requests per IP:"])
            for ip, request in self.request_count_per_ip().items():
                writer.writerow([ip,request])
            
            writer.writerow([""])

            writer.writerow(["Most Accessed Endpoint:"])
            for endpoint, count in self.frequent_access_endpoint().items():
                writer.writerow([endpoint,count])
            
            writer.writerow([""])
            
            writer.writerow(["Suspicious Activity:"])
            for ip, failed_attepmt in self.detect_suspicious_activity().items():
                writer.writerow([ip, failed_attepmt])
            

    def main(self):
        self.output_csv()
        

if __name__ == '__main__':
   log = Log_Analysis(file_path="sample.log")
   log.main()
