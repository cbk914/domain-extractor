# domain-extractor
Domain-extractor is a Python script that extracts domain names from a text file, URL, or zone file. It supports resolving IP addresses to domain names and checking domain status codes and redirections.

# Installation:

Ensure you have Python 3.6 or higher installed on your system. You can download Python from the official website: https://www.python.org/downloads/

	git clone https://github.com/cbk914/domain-extractor.git

Create a virtual environment (optional, but recommended):

	python -m venv venv

Activate the virtual environment:

On Linux and macOS:

	source venv/bin/activate

On Windows:

	venv\Scripts\activate

Install the required packages using the following command:
 
	pip install -r requirements.txt

# Usage:
To run the domain-extractor script, use one of the following commands depending on the input source:

To extract domains from a URL:

	python domain-extractor.py -u https://example.com -o output.txt

To extract domains from a file (txt, html, csv, json, or xml):

	python domain-extractor.py -f input_file.ext -o output.txt

To extract domains from a zone file:

	python domain-extractor.py -z zone_file -o output.txt

To check the status codes and redirections of domains in a file:

	python domain-extractor.py -c domains_to_check.txt

Note: Replace input_file.ext, zone_file, and domains_to_check.txt with the appropriate filenames or paths on your local machine. Also, replace output.txt with the desired output filename, in txt, html, csv, json, or xml format.