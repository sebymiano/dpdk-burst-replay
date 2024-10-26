#ifndef CSV_TO_JSON_H
#define CSV_TO_JSON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 1024
#define MAX_FIELD_LENGTH 256

/**
 * @brief Converts a CSV file to a JSON file.
 *
 * This function reads data from a CSV file and writes it to a JSON file.
 * The first row of the CSV file is expected to contain the headers, which will
 * be used as the keys in the JSON objects.
 *
 * @param csv_filename The path to the input CSV file.
 * @param json_filename The path to the output JSON file.
 */
void csv_to_json(const char* csv_filename, const char* json_filename);

#endif  // CSV_TO_JSON_H