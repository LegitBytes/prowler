import json
import sys
def count_controls(file_path: str):
    """This is used to check the number of controls present in a single compliance file

    Args:
        file_path (str): a valid relative path to compliance json file

    Returns:
        count ( int ) : The count of the controls  
    """
    try:
        
        with open(file_path, "r") as file:
            json_data: dict = json.load(file)
        requirements: list = json_data.get("Requirements", [])
        count = sum(1 for req in requirements if "Id" in req)
        return count
    
    except FileNotFoundError:
        return "Error: File not found."
    except json.JSONDecodeError:
        return "Error: Invalid JSON format."
    except Exception as e:
        return f"Unexpected Error: {str(e)}"
 
if __name__ == "__main__":
    args = sys.argv
    if(len(args) < 2):
        print("Usage python3 count_controls.py <file_path>")
        sys.exit(1)
    file_path = args[1]
    result = count_controls(file_path=file_path)
    print(result)