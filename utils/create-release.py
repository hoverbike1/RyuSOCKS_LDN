#!/usr/bin/env python3
import argparse
import subprocess

from datetime import date
from pathlib import Path


def is_repo_dirty(repo_dir: Path) -> bool:
    git_status_process = subprocess.run(
        ["git", "status", "--porcelain"],
        stdout=subprocess.PIPE,
        cwd=repo_dir,
        check=True,
    )
    return len(git_status_process.stdout) > 0


def git_commit(repo_dir: Path, message: str):
    subprocess.run(
        ["git", "commit", "-a", "-m", message],
        cwd=repo_dir,
        check=True,
    )


def git_tag(repo_dir: Path, tag_name: str):
    subprocess.run(
        ["git", "tag", tag_name],
        cwd=repo_dir,
        check=True,
    )


def modify_changelog(changelog_path: Path, version: str, tag_name: str) -> list[str]:
    section_index = -1
    changes = []

    with open(changelog_path, "r") as file:
        text = file.readlines()

    # Search for the unreleased section
    for i in range(len(text)):
        if text[i].startswith("## [Unreleased]"):
            # Skip over the next (blank) line
            section_index = i + 2
            break

    # Abort if we couldn't find the unreleased section
    if section_index == -1:
        raise Exception(f"Couldn't find the unreleased section in: {changelog_path}")

    # Insert the new release section
    text.insert(section_index, "\n")
    text.insert(section_index, f"## [{version}] - {date.today().isoformat()}\n")

    # Copy all changes for this release into an array
    for i in range(section_index + 2, len(text)):
        # NOTE: This requires other releases or the bottom reference section to exist
        if not text[i].startswith("## ") and not text[i].startswith("["):
            changes.append(text[i])
        else:
            # Remove the last (blank) line from the changes array
            changes.pop()
            break

    is_first_release = False
    # Iterate through the rest of the file to find and modify the references
    for j in range(i, len(text)):
        # NOTE: This requires the bottom reference section to exist
        if text[j].startswith("[Unreleased]: "):
            # NOTE: This requires the reference to be a GitHub URL
            # Check if this is the first release
            if "/tree/" in text[j]:
                base_url = (
                    text[j].rsplit("/tree/", maxsplit=1)[0].split(" ", maxsplit=1)[1]
                )
                is_first_release = True
            else:
                base_url = (
                    text[j].rsplit("/compare/", maxsplit=1)[0].split(" ", maxsplit=1)[1]
                )

            # Modify the unreleased reference for the new tag
            text[j] = f"[Unreleased]: {base_url}/compare/{tag_name}...HEAD\n"

            # Add the reference for the new release
            if is_first_release:
                # For the first release only link to the tag
                text.insert(j + 1, f"[{version}]: {base_url}/releases/tag/{tag_name}\n")
            else:
                # Get the previous release tag from the next line
                # Check if the previous release was the first release
                if "/releases/tag/" in text[j + 1]:
                    previous_tag_name = (
                        text[j + 1].rsplit("/releases/tag/", maxsplit=1)[1].strip()
                    )
                else:
                    previous_tag_name = (
                        text[j + 1]
                        .rsplit("/compare/", maxsplit=1)[1]
                        .split("...", maxsplit=1)[1]
                        .strip()
                    )

                text.insert(
                    j + 1,
                    f"[{version}]: {base_url}/compare/{previous_tag_name}...{tag_name}\n",
                )
            break

    # Write the changes back to the changelog file
    with open(changelog_path, "w") as file:
        file.writelines(text)

    # Return the changes for this release
    return changes


def modify_csproject(csproj_path: Path, version: str, changes: list[str]) -> list[str]:
    release_notes_index = -1

    with open(csproj_path, "r") as file:
        text = file.readlines()

    # Search for and modify the version tag
    for i in range(len(text)):
        # NOTE: This requires <Version> and </Version> to be in the same line
        if text[i].strip().startswith("<Version>"):
            # Replace the value with the new version
            old_version = (
                text[i]
                .strip()
                .rsplit("</Version>", maxsplit=1)[0]
                .split("<Version>", maxsplit=1)[1]
            )
            text[i] = text[i].replace(old_version, version)
            break

    # Keep a copy of csproj file with the modified version to return later
    modified_version_csproj_text = text.copy()

    # Modify PackageReleaseNotes if required
    if len(changes) > 0:
        # Search for the PackageReleaseNotes closing tag
        for i in range(len(text)):
            # NOTE: This requires the closing tag to be the first/only text on this line
            if text[i].strip().startswith("</PackageReleaseNotes>"):
                release_notes_index = i
                break

        # Abort if we couldn't find the PackageReleaseNotes closing tag
        if release_notes_index == -1:
            raise Exception(
                f"Couldn't find the PackageReleaseNotes closing tag in: {csproj_path}"
            )

        # Insert Markdown divider
        text.insert(release_notes_index, "\n---\n\n")
        release_notes_index += 1

        # Insert release changes line by line
        for change in changes:
            text.insert(release_notes_index, change)
            release_notes_index += 1

    # Write the changes back to the csproj file
    with open(csproj_path, "w") as file:
        file.writelines(text)

    # Return the contents of the csproj file with the modified version
    return modified_version_csproj_text


REPO_DIR = Path(__file__).parent.parent
CHANGELOG_PATH = REPO_DIR.joinpath("CHANGELOG.md")
CSPROJECT_PATH = REPO_DIR.joinpath("RyuSocks", "RyuSocks.csproj")

parser = argparse.ArgumentParser()
parser.add_argument("version", help="The new version to release")

args = parser.parse_args()

# Make sure git repository is not dirty
if is_repo_dirty(REPO_DIR):
    print("Repository is dirty, refusing to execute.")
    exit(1)

# Create the name of the git tag
tag_name = f"v{args.version}"

print(f"Creating a new release for version '{args.version}' with tag: {tag_name}")

# Modify the files
print(f"Modifying {CHANGELOG_PATH}...")
release_changes = modify_changelog(CHANGELOG_PATH, args.version, tag_name)
print(f"Found {len(release_changes)} changelog entries for this release.")
print(f"Modifying {CSPROJECT_PATH}...")
csproj_contents_without_notes = modify_csproject(
    CSPROJECT_PATH, args.version, release_changes
)

# Commit the modified files for the new release
print("Committing modified files for new release...")
git_commit(REPO_DIR, f"Release {tag_name}")
# Tag the release
print("Tagging release...")
git_tag(REPO_DIR, tag_name)

# Remove the release note changes from the csproj file
print(f"Removing release note changes from {CSPROJECT_PATH}...")
with open(CSPROJECT_PATH, "w") as file:
    file.writelines(csproj_contents_without_notes)

# Commit the changes
print("Committing modified files for post-release cleanup...")
git_commit(REPO_DIR, "Perform post-release cleanup")

print("Done!")
