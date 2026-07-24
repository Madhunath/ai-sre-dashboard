import getpass

from admin.auth import create_admin_user


def main() -> None:
    username = input("Admin username: ").strip()
    password = getpass.getpass("Admin password: ")
    if not username or not password:
        raise SystemExit("Username and password are required.")

    create_admin_user(username, password)
    print(f"Admin user '{username}' created or updated.")


if __name__ == "__main__":
    main()
