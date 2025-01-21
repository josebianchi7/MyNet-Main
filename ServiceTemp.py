# Author: Jose Bianchi
# Description: Code reads .txt file for some keyword, and overwrites if needed.

import os
import time

# Get .txt file for microservice from path
# SPECIFY TARGET FILE AND KEYWORD VARIABLES
target_filename = 'PLACEHOLDER.txt'
keyword = 'PLACEHOLDER'
file_found = False
filename = None

# Find file if it exists 
current_dir = os.listdir()
for file in current_dir:
    if file == target_filename:
        file_found = True
        filename = file
if file_found == False:
    raise FileNotFoundError(f"The file '{target_filename}' does not exist in the current directory.")

# Run main function continuously while file exists
while file_found:
    # Sleep for 1 second
    time.sleep(1)

    # Open file for read and write
    with open(filename, 'r+') as file:
        all_lines = file.readlines()

        # # Overwrite file from beginning
        # file.seek(0)
        # prng_file.writelines()
        # # Remove any old content leftover
        # prng_file.truncate()

    # Close file
    file.close()
