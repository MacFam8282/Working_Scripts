def validate_age(age):
    if age < 0:
        raise ValueError("Age cannot be negative!")
    if age > 120:
        raise ValueError("Age cannot be greater than 120!")
print("Age is valid.")
# Test the function with an invalid age
validate_age(130)