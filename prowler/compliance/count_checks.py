import sys
import json

def count_checks(file_path: str):
    try:
        with open(file_path, "r") as file:
            data = json.load(file)
            requirements = data.get("Requirements", [])
            all_checks = []
            for requirement in requirements:
                # Get the list of checks (or an empty list if missing)
                checks = requirement.get("Checks", [])
                # Extend the list with individual check strings
                all_checks.extend(checks)
        # Return the count of unique check names
        return len(set(all_checks))
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 count_checks.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    result = count_checks(file_path)
    print(result)
