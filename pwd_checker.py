import re
import sys

def check_password_strength(password):
    strong_password_regex = re.compile(
        r'^(?=.*[a-z])'
        r'(?=.*[A-Z])'
        r'(?=.*\d)'
        r'(?=.*[@$!%*?&.])'
        r'[A-Za-z\d@$!%*?&.]{8,}$'
    )
    if len(password) < 8:
        return "Weak: Password must be at least 8 characters long"
    elif not strong_password_regex.match(password):
        return "Weak: Password must include at least one lowercase, uppercase, digit, special character and be 8+ characters long"
    else:
        return "Strong password"

def main():
    if len(sys.argv) < 2:
        print("Usage: python pwd_checker.py <password>")
        sys.exit(1)
    password = sys.argv[1]
    result = check_password_strength(password)
    print(result)

if __name__ == "__main__":
    main()
