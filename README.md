# CVEsploit
**Description:** CVEsploit is a Python script that allows you to search for Common Vulnerabilities and Exposures (CVE) information using the Metasploit Framework. By providing a list of CVE identifiers, the tool queries the Metasploit Framework to find relevant modules, including those marked as auxiliary. The script generates CSV files containing the results, including the matching modules for each CVE and the auxiliary modules available.

**Features:** CVE Check Search: Find matching modules for a specific CVE that supports checks, to ensure no systems will be damaged. CVE All Search: Retrieve all modules associated with a particular CVE, regardless of the availability for a safe check. Auxiliary Module Search: Identify all auxiliary modules related to a CVE.

**Usage:**
1) Install the required dependencies (ensure Metasploit Framework is installed).
2) Run the script with the following command: python CVEsploit.py <cve_list_file>, where <cve_list_file> is a text file containing a list of CVE identifiers, one per line.
3) The script will query the Metasploit Framework for each CVE, retrieve the matching modules, and generate separate CSV files for different types of modules.
4) The generated CSV files will be stored in the results directory, named with the date of execution.

**Note:** Make sure to have the Metasploit Framework installed and configured properly for the tool to work correctly.

Feel free to modify and enhance the tool to suit your specific needs. Happy vulnerability searching!
