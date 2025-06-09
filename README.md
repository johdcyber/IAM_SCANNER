
# Johndcyber IAM Resource Scanner

The Johndcyber IAM Resource Scanner is a Python script designed to detect overly permissive AWS IAM policies and list the roles attached to these policies. It outputs the results to a CSV file with columns for the resource, IAM policy, and a brief description of the access type (read or write).

## Features

- Scans all IAM policies in your AWS account.
- Scans both managed and inline IAM role policies.
- Identifies overly permissive policies (e.g., policies with `*` actions or resources).
- Lists roles attached to the identified policies.
- Describes the type of access (read or write) granted by the policies.
- Outputs the results to a CSV file (`overly_permissive_policies.csv`).
- Logs the scanning process and errors to a log file (`johndcyber_iam_scanner.log`).

## Prerequisites

- Python 3.6 or later.
- AWS credentials configured (e.g., via AWS CLI or environment variables).

## Installation

1. Clone this repository or download the script file (`johndcyber_iam_scanner.py`).

2. Install the required Python library:
    \`\`\`bash
    pip install boto3
    \`\`\`

3. Ensure your AWS credentials are configured. You can set up your credentials by following the AWS documentation for configuring the AWS CLI or by setting environment variables.

## Usage

1. Save the script to a file named `johndcyber_iam_scanner.py`.

2. Run the script using Python:
    \`\`\`bash
    python johndcyber_iam_scanner.py [--debug]
    \`\`\`

3. The script will log its progress and any errors encountered to both the console and a log file named `johndcyber_iam_scanner.log`. Use the `--debug` flag for verbose output.

4. The results will be written to a CSV file named `overly_permissive_policies.csv` with the following columns:
    - `Resource`: Roles attached to the overly permissive policy.
    - `IAM Policy`: Name of the overly permissive policy.
    - `Access Type`: Brief description of the access type (read or write).

## Example Output

The `overly_permissive_policies.csv` file will look like this:

\`\`\`
Resource,IAM Policy,Access Type
Role1,Role2,PolicyName,read, write
Role3,PolicyName,write
No roles attached,PolicyName,read
\`\`\`

## Logging

The script logs its progress and any errors to `johndcyber_iam_scanner.log`. This log file can help diagnose any issues encountered during the scan.

## Contributing

Contributions are welcome! If you have any suggestions or improvements, please submit a pull request or open an issue.

## License

This project is licensed under the MIT License.

## Acknowledgements

The script uses the `boto3` library to interact with AWS services.
