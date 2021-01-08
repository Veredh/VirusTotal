import requests


class VirusTotalAPI:
    URL = 'https://www.virustotal.com/vtapi/v2/file/report'
    PARAM_API_KEY = 'apikey'
    PARAM_RESOURCE = 'resource'
    API_KEY = "d002b6563631194c0df37ed38eca55ecf6222a3566b4ba8dd10b9d6be1f171ab"

    SCANNED_FILES_TABLE = 'Scanned File'
    SCANNED_FILES_FIELDS = ['md5', 'sha1', 'sha256']
    SCANNED_FILES_COLUMNS = ['MD5', 'SHA-1', 'SHA-256']

    RESULTS_TABLE = 'Results'
    RESULTS_FIELDS = ['total', 'positive']
    RESULTS_COLUMNS = ['Total Scans', 'Positive Scans']

    SCANS_TABLE = 'Scans'
    SCANS_COLUMNS = ['Scan Origin', 'Scan Result']
    SCANS_FIELDS = 'scans'

    RESULT = 'result'

    TABLE_COLUMNS = {SCANNED_FILES_TABLE: SCANNED_FILES_COLUMNS, RESULTS_TABLE: RESULTS_COLUMNS,
                     SCANS_TABLE: SCANS_COLUMNS}
    JSON_FIELDS = {SCANNED_FILES_COLUMNS[0]: SCANNED_FILES_FIELDS[0],
                   SCANNED_FILES_COLUMNS[1]: SCANNED_FILES_FIELDS[1],
                   SCANNED_FILES_COLUMNS[2]: SCANNED_FILES_FIELDS[2],
                   RESULTS_COLUMNS[0]: RESULTS_FIELDS[0],
                   RESULTS_COLUMNS[1]: RESULTS_FIELDS[1]}

    HTTP_RESPONSE_SUCCESS = 200

    def create_markdown_table_from_virus_total(self, users_input):
        """
        :param users_input: hash representation of a file (MD5, SHA-1 or SHA-256)
        :return: markdown tables of the data that return from Virus Total on that file
        """
        try:
            virus_total_response = self.get_json_from_virus_total(users_input)

            scanned_files_dictionary = self.create_dictionary(virus_total_response,
                                                              self.SCANNED_FILES_TABLE)
            results_dictionary = self.create_dictionary(virus_total_response,
                                                        self.RESULTS_TABLE)
            scans_dictionary = self.create_scans_dictionary(virus_total_response)

            markdown_table = MarkdownTable()
            markdown_string = ""
            markdown_string += markdown_table.create_markdown_table(self.SCANNED_FILES_TABLE,
                                                                    self.SCANNED_FILES_COLUMNS,
                                                                    scanned_files_dictionary)
            markdown_string += markdown_table.create_markdown_table(self.RESULTS_TABLE,
                                                                    self.RESULTS_COLUMNS,
                                                                    results_dictionary)
            markdown_string += markdown_table.create_markdown_table(self.SCANS_TABLE,
                                                                    self.SCANS_COLUMNS,
                                                                    scans_dictionary)
            print(markdown_string)
        except ValueError as error:
            print(f"An error occurred while trying to retrieve data from server!\nError Message: {error}")
        except Exception as e:
            print(f"Something went wrong while trying to fetch data from server\nError message: {e}")

    def get_json_from_virus_total(self, users_input):
        url = self.URL
        params = {self.PARAM_API_KEY: self.API_KEY, self.PARAM_RESOURCE: users_input}
        response = requests.get(url, params=params)

        if response.status_code == self.HTTP_RESPONSE_SUCCESS:
            json = response.json()
            if not json['response_code']:
                raise Exception(json['verbose_msg'])
            else:
                return json
        else:
            raise ValueError(f"Request from server responded error code number: {response.status_code}")

    def create_dictionary(self, json_response, table_name):
        """
        :param json_response: Virus Total's json response on the submitted file
        :param table_name: The table on which we retrieve the data
        :return: Dictionary in which its keys are the table columns, and the values are the columns content
        """
        new_dictionary = {}

        for value in self.TABLE_COLUMNS[table_name]:
            new_dictionary[value] = json_response.get(self.JSON_FIELDS[value])

        return new_dictionary

    def create_scans_dictionary(self, json_response):
        """
        :param json_response: Virus Total's json response on the submitted file
        :return: Dictionary in which the keys are the 'Scan Origin' and the values are the 'Scan Result'
        """
        new_dictionary = {}
        scans_origin = []
        scans_result = []
        scans_dictionary_from_json = json_response.get(self.SCANS_FIELDS)

        for value in scans_dictionary_from_json:
            new_dictionary[value] = scans_dictionary_from_json[value].get(self.RESULT)
            scans_origin.append(value)
            scans_result.append(scans_dictionary_from_json[value].get(self.RESULT))

        return new_dictionary


class MarkdownTable:
    SCANS_TABLE = 'Scans'

    def create_initial_markdown_string(self, table_name, table_columns):
        """
        :param table_name: The name of the table to add to the beginning of the markdown string
        :param table_columns: The columns of the table to add to the markdown string
        :return: The initial markdown string without the columns content
        """
        markdown_string = f"## {table_name}\n|"

        for column in table_columns:
            markdown_string += f" {column} |"

        markdown_string += "\n|"
        for i in range(len(table_columns)):
            markdown_string += " :---: |"

        markdown_string += "\n|" if table_name != self.SCANS_TABLE else ""

        return markdown_string

    def create_markdown_table(self, table_name, table_columns, dictionary):
        """
        :param table_name: The name of the current table
        :param table_columns: The names of the table columns
        :param dictionary: The data of the current table
        :return: Markdown string which represents the full table data
        """
        markdown_string = self.create_initial_markdown_string(table_name, table_columns)

        if table_name != self.SCANS_TABLE:
            for item in dictionary:
                markdown_string += f" {dictionary[item]} |"
        else:
            for item in dictionary:
                markdown_string += f"\n| {item} | {dictionary[item]} |"

        markdown_string += "\n"

        return markdown_string


if __name__ == "__main__":
    virus_total_api = VirusTotalAPI()
    user_input = input("Please insert a hash representation of a file: ")
    virus_total_api.create_markdown_table_from_virus_total(user_input)
