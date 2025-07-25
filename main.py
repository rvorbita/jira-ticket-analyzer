"""
Project: JIRA Ticket Analyzer
Author: Raymart Orbita
Email: raymart.orbita@infor.com
Date: 2025-07-18
Version: 1.0.0
Description: Parses ADF(atlassian document format) JSON and extracts relevant Jira fields.
"""

import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
import re
import os
import sys

# --- Functions ---
def find_text_after_label(adf_doc, label):
    """Recursively find the text that follows a specific label in Atlassian Document Format structured content."""
    # This function searches through the ADF document structure to 
    # find the text that follows a specific label.
    def extract_texts(content_list):
        # Check if the content_list is a list
        if not isinstance(content_list, list):
            return None
        # Iterate through the content_list to find the label
        # and return the next non-empty text item
        for i, item in enumerate(content_list):
            # Check if the item is a text type and matches the label
            if item.get("type") == "text" and label.lower() in item.get("text", "").strip().lower():
                # Get next non-empty text
                for next_item in content_list[i + 1:]:
                    # Check if the next item is a text type and not empty
                    if next_item.get("type") == "text" and next_item.get("text", "").strip():
                        return next_item["text"].strip()
            # Elif the item is a paragraph or a block with content, recurse into it
            elif "content" in item:
                # Recursively call extract_texts on the content of the item
                result = extract_texts(item["content"])
                # If a result is found in the recursive call, return it
                if result:
                    return result
        return None

    # Start the extraction process from the ADF document
    return extract_texts(adf_doc.get("content", []))

def extract_actions_taken_bullets(node):
    """
    Recursively search for bullet list items under a node labeled "Actions Taken".
    Returns list of bullet texts or None if not found.
    """

    def is_actions_taken_label(item):
        if item.get("type") in ("paragraph", "heading"):
            texts = [t.get("text", "").lower() for t in item.get("content", []) if t.get("type") == "text"]
            joined_text = " ".join(texts).strip()
            return "actions taken" in joined_text
        return False

    def extract_bullets_from_list(bullet_list_node):
        bullets = []
        for list_item in bullet_list_node.get("content", []):
            for para in list_item.get("content", []):
                for text_obj in para.get("content", []):
                    if text_obj.get("type") == "text":
                        bullets.append(text_obj.get("text", ""))
        return bullets

    # If node is a dict and has content, recursively scan
    if isinstance(node, dict):
        content = node.get("content", [])
        for i, item in enumerate(content):
            # Found label "Actions Taken"
            if is_actions_taken_label(item):
                # Check immediate siblings for bulletList
                bullets = []
                # Check next siblings for bulletList nodes (sometimes multiple)
                for sibling in content[i+1:]:
                    if sibling.get("type") == "bulletList":
                        bullets.extend(extract_bullets_from_list(sibling))
                    else:
                        # stop if next sibling is not a bulletList (optional)
                        break
                if bullets:
                    return bullets
            else:
                # Recursive search in this item
                found = extract_actions_taken_bullets(item)
                if found:
                    return found

    # If node is a list, recurse each item
    elif isinstance(node, list):
        for item in node:
            found = extract_actions_taken_bullets(item)
            if found:
                return found

    return None

def validate_jira_tag():
    """Prompt and validate the Jira tag input from the user."""
   
    try:
        # Prompt the user for the Jira tag
        jira_tag = input("Enter the Jira tag (e.g., CSLC-27668): ").strip()
        # Validate the Jira tag format raise an error if it doesn't match the expected format
        if not jira_tag.startswith(("CSLC-", "CS-")) or not jira_tag.split("-")[1].isdigit():
            raise ValueError
        return jira_tag
    except KeyboardInterrupt:
        # Handle keyboard interrupt gracefully
        print("\nProcess interrupted by user.")
        sys.exit(0)
    except:
        # Handle invalid Jira tag format
        print("Invalid Jira tag. Please enter a valid Jira tag in the format 'CSLC-XXXXXX'.")
        sys.exit(0)


def fetch_issue_data(jira_tag):
    """Make a GET request to the Jira API and return the issue data."""
    # --- Load Environment Variables ---
    # Reload updated .env variables
    load_dotenv(override=True)
    JIRA_URL = "https://infor.atlassian.net/rest/api/3/issue"
    EMAIL = os.getenv("JIRA_EMAIL")
    API_TOKEN = os.getenv("JIRA_API_TOKEN")

    # Construct the URL for the Jira API request
    url = f"{JIRA_URL}/{jira_tag}"
    auth = HTTPBasicAuth(EMAIL, API_TOKEN)
    headers = {"Accept": "application/json"}

    # Make the GET request to the Jira API
    response = requests.get(url, headers=headers, auth=auth)

    # Check if the response is successful or not exit if failed
    if response.status_code != 200:
        try:
            error_status = response.status_code
            error_info = response.json()
            error_messages = error_info.get("errorMessages", [])
            if error_messages:
                message = "\n".join(error_messages)
            else:
                message = "An error occurred, but no error message was provided."
        except ValueError:
            message = response.text.strip()

        raise Exception("Status Code " + " " +str(error_status) + ", " + message)

    return response.json()


def extract_issue_fields(issue):
    """Extract and return relevant fields from the issue dictionary."""
    # Get the fields from the issue
    fields = issue.get("fields", {})
    description = fields.get("description", {})
    # print(fields) # for debugging purposes, print the fields structure json
    # print(description) # For debugging purposes, print the description structure json

    action_taken_text = find_text_after_label(description, "Actions Taken")
    action_taken_bullets = extract_actions_taken_bullets(description)


    # Return a dictionary with the extracted fields
    return {
        "components": [c["name"] for c in fields.get("components", [])],
        "labels": fields.get("labels", []),
        "fix_versions": [v["name"] for v in fields.get("fixVersions", [])],
        "affects_versions": [v["name"] for v in fields.get("versions", [])],
        # "environment": fields.get("environment", {}).get("content", [{}])[0].get("content", [{}])[0].get("text", ""),
        "environment": get_environment_text(fields), # use helper function to prevent the Error: list index out of range
        "original_estimate": fields.get("timetracking", {}).get("originalEstimate", "N/A"),
        "time_spent": fields.get("timetracking", {}).get("timeSpent", "N/A"),
        "description": find_text_after_label(description, "Describe the issue in detail"),
        "base_patch_package": find_text_after_label(description, "Base Patch Package"),
        # "action_taken": find_text_after_label(description, "Actions Taken"),
        "action_taken_text": action_taken_text,
        "action_taken_bullets": action_taken_bullets,
        "known_customizations": find_text_after_label(description, "Known Customizations"),
        "error_logs": find_code_black_label(description, "codeBlock"),
        "attached_files": [f["filename"] for f in fields.get("attachment", []) if f.get("filename")],
        "summary": fields.get("summary", "No summary provided"),
    }


def get_patch_end_number(version_string):
    """Extract the last 2 or 3 components of a version string."""
    # Split the version string into parts
    parts = version_string.split('.')
    last_2 = '.'.join(parts[-1:]) # Get the last two parts
    last_3 = '.'.join(parts[-2:]) # Get the last three

    # Check the length of the version string to determine which parts to return
    if len(version_string) < 7:
        return last_2
    else:
        return last_3
    

def clean_version_string(version_str):
    """
    Extract the numeric version from a version string, e.g.,
    "10.1.1.27( version the customer is currently on)" -> "10.1.1.27"
    """
    # Use regex to find the first numeric version pattern
    match = re.match(r"[\d\.]+", version_str)
    return match.group(0) if match else None


def compare_patch_and_affect_version(base_patch, affect_version):
    """Compare the base patch package with the fix versions."""
    # Check if the base patch and affect version are provided
    if not base_patch or not affect_version:
        print("Base patch package or fix versions are missing.")

    # Clean the base patch and affect version strings
    base_patch_end_number_clean = clean_version_string(base_patch)
    affect_version_end_number_clean = clean_version_string(affect_version[0])
    
    try:
        # Check if the cleaned version strings are valid
        # Extract the trailing patch numbers
        base_end = get_patch_end_number(base_patch_end_number_clean)
        affect_end = get_patch_end_number(affect_version_end_number_clean)

        # Normalize to float and back to string
        base_str = str(float(base_end))
        affect_str = str(float(affect_end))

        # Remove leading digit and dot if format is like "1.29" -> "29"
        if len(base_str) > 2 and base_str[1] == '.':
            base_str = base_str[2:]
 
        if len(affect_str) > 2 and affect_str[1] == '.':
            affect_str = affect_str[2:]

        # Remove the leading digit if the format is like 27.1 -> "27"
        if len(base_str) > 2 and base_str[2] == '.':
            base_str = base_str[:2]

        if len(affect_str) > 2 and affect_str[2] == '.':
            affect_str = affect_str[:2]

        # Get first digit to compare
        base_digit = int(base_str)
        affect_digit = int(affect_str)

        # print(base_digit, affect_digit)
       
        # Compare the base patch number with the affect version number
        if int(base_digit) > int(affect_digit):
            return f"FAILED : Base patch package {base_digit} is higher than the Affect version {affect_digit}"
            # return f"FAILED: Please check Base patch package and Affects Version"
            
        elif int(base_digit) == int(affect_digit):
            return f"FAILED : Base patch package and Affect version are the same: {base_digit} == {affect_digit}"
            
        else:
            return None
            
        
    except Exception as e:
        # Handle unexpected errors during comparison
        return f"An unexpected error occurred during comparison. {e}"



def find_code_black_label(data, label):
    """
    Find text from codeBlock in JSON data
    """
    if label == "codeBlock":
        return find_codeblock(data)
    return None

def find_codeblock(obj):
    """
    Search for codeBlock and get its text
    """
    # If it's a dictionary
    if isinstance(obj, dict):
        # Check if this is a codeBlock
        if obj.get('type') == 'codeBlock':
            # Get the text from content
            content = obj.get('content', [])
            for item in content:
                if item.get('type') == 'text':
                    text = item.get('text', '')
                    # Clean the text
                    clean_text = text.replace('\\n', '\n')
                    clean_text = clean_text.replace("\\'", "'")
                    return clean_text
        
        # Search in all values
        for value in obj.values():
            result = find_codeblock(value)
            if result:
                return result
    
    # If it's a list
    elif isinstance(obj, list):
        for item in obj:
            result = find_codeblock(item)
            if result:
                return result
    
    return None


def get_environment_text(fields):
    #safely extract the "text" from from nested structure
    try:
        return (
            fields.get("environment", {})
            .get("content", [])[0]
            .get("content", [])[0]
            .get("text", "")
        )
    except (IndexError, AttributeError, TypeError):
        return None


def get_bullet_list_text(fields, key):
    """
    Safely extract bullet list text items from a nested structure under the given key.
    Returns a list of strings or None if not found.
    """
    try:
        bullet_list = fields.get(key, {})
        if bullet_list.get("type") != "bulletList":
            return None
        
        bullets = []
        for list_item in bullet_list.get("content", []):
            for paragraph in list_item.get("content", []):
                for text_obj in paragraph.get("content", []):
                    if text_obj.get("type") == "text":
                        bullets.append(text_obj.get("text", ""))
        return bullets if bullets else None
    except (AttributeError, IndexError, TypeError):
        return None


def print_issue_summary(data):
    """Display the extracted issue fields in a readable format and collect findings."""

    # Dict to hold the findings 
    findings = {}

    def display(label, value):
        print(f" * {label}: {value if value else f'No {label.lower()} provided.'}")

    print("\n\nIssue Details:\n")

    display("Summary", data.get("summary"))
    display("Base Patch Package", data.get("base_patch_package"))
    display("Affects Versions", ", ".join(data.get("affects_versions", [])))
    # display("Environment", data.get("environment"))

    # check if the environment if None or with text provided.
    if data.get("environment") == None:
        findings["Environment"] = "Missing or invalid error logs. Please provide plain text logs, not images or attachments."
    else:
        display("Environment", data.get("environment"))

    # display("Description", data.get("description")) # temporarly remove the description
    # display("Actions Taken", data.get("action_taken"))
    # check if the action_taken is in bulletList if not print in a single line.
    bullets = data.get("action_taken_bullets")
    if bullets:
        print(" * Actions Taken:")
        for bullet in bullets:
            print(f"   - {bullet}")
    else:
        display("Actions Taken", data.get("action_taken_text"))

    # check for label name unplanned and cslc-ops-svcdesk
    # if unplanned and cslc-ops-svcdesk missing add to findings and print to the gui.
    labels = data.get("labels", [])
    missing_labels = []
    if "unplanned" not in labels:
        missing_labels.append("'unplanned'")
    if "CSLC-OPS-SVCDESK" not in labels:
        missing_labels.append("'CSLC-OPS-SVCDESK'")

    if missing_labels:
        findings["Labels"] = f"Missing required labels: {', '.join(missing_labels)}"
        print(f" * Labels: Failed - {findings['Labels']}")
    else:
        display("Labels", ", ".join(labels))

    # check for error_logs if None print message.
    if data.get("error_logs"):
        display("Error Text", "Error text found.")
        # print(data.get("error_logs"))
    else:
        findings["Error Text"] = "Missing or invalid error logs. Please provide plain text logs, not images or attachments."


    display("Attached Files", ", ".join(data.get("attached_files", [])))

    # Compare base patch with affect versions
    compare = compare_patch_and_affect_version(data.get("base_patch_package"), data.get("affects_versions"))
    if compare:
        findings["Patch Comparison"] = compare

    # Print findings
    print("\nIssue Findings:\n")
    if findings:
        for key, note in findings.items():
            display(key, note)
    else:
        print(" * No issues found.")


# --- Main Execution ---
def main():
    jira_tag = validate_jira_tag()
    issue_data = fetch_issue_data(jira_tag)
    extracted_data = extract_issue_fields(issue_data)
    print_issue_summary(extracted_data)


if __name__ == "__main__":
    main()
