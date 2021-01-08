import requests

URL = 'https://www.virustotal.com/vtapi/v2/file/report'
PARAM_API_KEY = 'apikey'
PARAM_RESOURCE = 'resource'
API_KEY = "d002b6563631194c0df37ed38eca55ecf6222a3566b4ba8dd10b9d6be1f171ab"
RESOURCE = "84c82835a5d21bbcf75a61706d8ab549"

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

TABLE_COLUMNS = {SCANNED_FILES_TABLE: SCANNED_FILES_COLUMNS, RESULTS_TABLE: RESULTS_COLUMNS, SCANS_TABLE: SCANS_COLUMNS}
JSON_FIELDS = {SCANNED_FILES_COLUMNS[0]: SCANNED_FILES_FIELDS[0],
               SCANNED_FILES_COLUMNS[1]: SCANNED_FILES_FIELDS[1],
               SCANNED_FILES_COLUMNS[2]: SCANNED_FILES_FIELDS[2],
               RESULTS_COLUMNS[0]: RESULTS_FIELDS[0],
               RESULTS_COLUMNS[1]: RESULTS_FIELDS[1]}

HTTP_RESPONSE_SUCCESS = 200


def get_json_from_virus_total():
    url = URL
    params = {PARAM_API_KEY: API_KEY, PARAM_RESOURCE: RESOURCE}
    response = requests.get(url, params=params)

    if response.status_code == HTTP_RESPONSE_SUCCESS:
        return response.json()
    else:
        raise ValueError(f"Request from server responded error code number: {response.status_code}")


def create_dictionary(json, table):
    new_dictionary = {}

    for value in TABLE_COLUMNS[table]:
        new_dictionary[value] = json.get(JSON_FIELDS[value])

    return new_dictionary


def create_scans_dictionary(json):
    new_dictionary = {}
    scans_origin = []
    scans_result = []
    scans_dictionary_from_json = json.get(SCANS_FIELDS)

    for value in scans_dictionary_from_json:
        new_dictionary[value] = scans_dictionary_from_json[value].get(RESULT)
        scans_origin.append(value)
        scans_result.append(scans_dictionary_from_json[value].get(RESULT))

    # initially thought to add as key the column name and as value its values,
    # but then realized it will be much easier to add a row as key and value
    # new_dictionary[SCANS_COLUMNS[0]] = scans_origin
    # new_dictionary[SCANS_COLUMNS[1]] = scans_result

    return new_dictionary


def create_initial_markdown_string(table_name, table_columns):
    markdown_string = f"## {table_name}\n|"

    for column in table_columns:
        markdown_string += f" {column} |"

    markdown_string += "\n|"
    for i in range(len(table_columns)):
        markdown_string += " :---: |"

    markdown_string += "\n|" if table_name != SCANS_TABLE else ""

    return markdown_string


def create_markdown_table(table_name, table_columns, dictionary):
    markdown_string = create_initial_markdown_string(table_name, table_columns)

    if table_name != SCANS_TABLE:
        for item in dictionary:
            markdown_string += f" {dictionary[item]} |"
    else:
        for item in dictionary:
            markdown_string += f"\n| {item} | {dictionary[item]} |"

    markdown_string += "\n"
    print(markdown_string)


if __name__ == "__main__":
    user_input = input("Please insert the representation you want to check: ")
    try:
        response_as_json = get_json_from_virus_total()
        scanned_files_dictionary = create_dictionary(response_as_json, SCANNED_FILES_TABLE)
        results_dictionary = create_dictionary(response_as_json, RESULTS_TABLE)
        scans_dictionary = create_scans_dictionary(response_as_json)
        create_markdown_table(SCANNED_FILES_TABLE, SCANNED_FILES_COLUMNS, scanned_files_dictionary)
        create_markdown_table(RESULTS_TABLE, RESULTS_COLUMNS, results_dictionary)
        create_markdown_table(SCANS_TABLE, SCANS_COLUMNS, scans_dictionary)
    except ValueError as error:
        print(f"An error occurred while trying to retrieve data from server!\nError Message: {error}")
