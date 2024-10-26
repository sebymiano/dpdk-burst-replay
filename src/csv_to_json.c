#include "csv_to_json.h"

// Helper function to trim newline and carriage return characters
void trim_newline(char* str) {
    str[strcspn(str, "\r\n")] = '\0';
}

void csv_to_json(const char* csv_filename, const char* json_filename) {
    FILE* csv_file = fopen(csv_filename, "r");
    FILE* json_file = fopen(json_filename, "w");

    if (csv_file == NULL || json_file == NULL) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    char line[MAX_LINE_LENGTH];
    char* headers[MAX_FIELD_LENGTH];
    int num_headers = 0;

    // Read the header line
    if (fgets(line, sizeof(line), csv_file)) {
        char* token = strtok(line, ",");
        while (token != NULL) {
            trim_newline(token);                     // Remove any newline or carriage return characters
            headers[num_headers++] = strdup(token);  // Store header fields
            token = strtok(NULL, ",");
        }
    }

    fprintf(json_file, "[\n");  // Start of JSON array

    int first_row = 1;
    // Read each line and convert to JSON object
    while (fgets(line, sizeof(line), csv_file)) {
        if (!first_row) {
            fprintf(json_file, ",\n");  // Comma between JSON objects
        }
        first_row = 0;

        fprintf(json_file, "  {\n");

        char* token = strtok(line, ",");
        for (int i = 0; i < num_headers && token != NULL; i++) {
            trim_newline(token);  // Trim newline characters from each value

            fprintf(json_file, "    \"%s\": \"%s\"", headers[i], token);
            token = strtok(NULL, ",");
            if (i < num_headers - 1) {
                fprintf(json_file, ",");
            }
            fprintf(json_file, "\n");
        }
        fprintf(json_file, "  }");
    }

    fprintf(json_file, "\n]\n");  // End of JSON array

    // Close files and free allocated memory
    fclose(csv_file);
    fclose(json_file);
    for (int i = 0; i < num_headers; i++) {
        free(headers[i]);
    }
}
