# domain-extractor

Generate a domain list from a text file, URL or zone file

Description:

domain-extractor.py is a Python script that extracts domain names from a URL, a file (txt, html, csv, json, or xml), or a zone file. It also supports resolving IP addresses to domain names and checking domain status codes and redirections.

# Installation:

Ensure you have Python 3.6 or higher installed on your system. You can download Python from the official website: https://www.python.org/downloads/

Download or clone the script domain-extractor.py and the requirements.txt file to a directory on your local machine.

Open a terminal or command prompt and navigate to the directory containing the script and requirements.txt.

Create a virtual environment (optional, but recommended):

	python -m venv venv

Activate the virtual environment:

On Linux and macOS:

	source venv/bin/activate

On Windows:

	venv\Scripts\activate

Install the required packages using the following command:

	pip install -r requirements.txt

Execution Instructions:

To run the domain-extractor.py script, use one of the following commands depending on the input source:

To extract domains from a URL:

	python domain-extractor.py -u https://example.com -o output.txt

To extract domains from a file (txt, html, csv, json, or xml):

	python domain-extractor.py -f input_file.ext -o output.txt

To extract domains from a zone file:

	python domain-extractor.py -z zone_file -o output.txt

To check the status codes and redirections of domains in a file:

	python domain-extractor.py -c domains_to_check.txt

