import asyncio
import httpx
import re
import json
import sys
import os
from contextlib import redirect_stdout, redirect_stderr

from xsint.config import get_config

# GitFive requires Python 3.10+ and must be installed separately via pipx
try:
    from gitfive.lib import metamon, github, emails_gen, organizations
    from gitfive.lib.domain_finder import guess_custom_domain
    from gitfive.lib.utils import delete_tmp_dir, detect_custom_domain
    from gitfive.lib.objects import GitfiveRunner
    from gitfive import config as gitfive_config
    GITFIVE_AVAILABLE = True
except Exception:
    GITFIVE_AVAILABLE = False

INFO = {
    "free": [],
    "paid": ["email", "username"],
    "returns": ["email", "profile_info", "ssh_keys"],
    "themes": {
        "GitFive": {"color": "grey39", "icon": "🐙"},
        "GitHub": {"color": "white", "icon": "👤"},
        "Email": {"color": "green", "icon": "📧"},
    },
}


async def _scrape_commits(runner, repo_name, emails_index):
    """
    Asyncio-compatible replacement for commits.scrape().
    GitFive's commits.scrape uses trio nurseries which can't run under asyncio.
    This does the same thing: fetch the commits page, parse the embedded JSON,
    and extract email -> username mappings.
    """
    out = {}
    url = f"https://github.com/{runner.creds.username}/{repo_name}/commits/mirage"
    req = await runner.as_client.get(url)

    if req.status_code != 200:
        return out

    # Parse the embedded JSON payload (same regex as commits.py)
    matches = re.findall(
        r'data-target="react-app\.embeddedData">(\{.*?\})<\/script>', req.text
    )
    if not matches:
        return out

    try:
        payload = json.loads(matches[0])
        commit_groups = payload.get("payload", {}).get("commitGroups", [])
        if not commit_groups:
            return out
        commits_list = commit_groups[0].get("commits", [])
    except (json.JSONDecodeError, KeyError, IndexError):
        return out

    for commit in commits_list:
        hexsha = commit.get("oid", "")
        if hexsha not in emails_index:
            continue

        authors = commit.get("authors", [])
        if len(authors) < 2:
            continue

        target_authors = [
            a for a in authors
            if a.get("displayName") != "gitfive_hunter" and a.get("login")
        ]
        if not target_authors:
            continue

        author = target_authors[0]
        email = emails_index[hexsha]
        out[email] = {
            "avatar": author.get("avatarUrl", ""),
            "username": author["login"],
            "is_target": False,  # Will be set after target.username is known
        }

    return out


async def run(session, target):
    results = []
    PARENT = "GitFive"

    if not GITFIVE_AVAILABLE:
        return 1, [{
            "label": "Not Installed",
            "value": "GitFive requires Python 3.10+ and must be installed via pipx: pipx install gitfive --python python3.10",
            "source": PARENT,
            "risk": "low",
        }]

    # FIX 1: Initialize this variable BEFORE the try block
    # This prevents "cannot access local variable" errors in the 'finally' block
    temp_repo_name = None

    # --- AUTH BRIDGE ---
    xsint_conf = get_config()
    gh_token = xsint_conf.get("github_token")

    if gh_token:
        gitfive_config.tokens = [gh_token]
        gitfive_config.headers["Authorization"] = f"token {gh_token}"

    # Monkey patch print to suppress DEBUG output from gitfive
    original_print = print

    def quiet_print(*args, **kwargs):
        if args and isinstance(args[0], str) and "[DEBUG]" in args[0]:
            return
        original_print(*args, **kwargs)

    import builtins

    builtins.print = quiet_print

    try:
        runner = GitfiveRunner()

        # FIX 2: PROXY SUPPORT
        # We hot-swap the internal client to inject the proxy configuration
        proxy = xsint_conf.get("proxy")
        if proxy:
            proxies_dict = {"http://": proxy, "https://": proxy}
            # Replace the default client with a proxied one
            # We must explicitly set verify=False when using proxies to avoid SSL errors
            proxied_client = httpx.AsyncClient(
                headers=gitfive_config.headers,
                timeout=gitfive_config.timeout,
                proxies=proxies_dict,
                verify=False,
            )
            # Must update BOTH references — runner.as_client is a snapshot
            # from __init__ that won't follow creds._as_client reassignment
            runner.creds._as_client = proxied_client
            runner.as_client = proxied_client

        # 1. Login
        try:
            await runner.login()
        except Exception as e:
            return 1, [
                {
                    "label": "Auth Error",
                    "value": "Check 'github_token'",
                    "source": PARENT,
                    "risk": "high",
                }
            ]

        # 2. Resolve target — email needs metamon lookup, username goes direct
        username = target
        if "@" in target:
            # Email flow: use metamon commit spoofing to resolve email -> username
            resolve_repo, emails_index = await metamon.start(runner, [target])
            emails_accounts = await _scrape_commits(runner, resolve_repo, emails_index)

            # Clean up the resolve repo
            try:
                await github.delete_repo(runner, resolve_repo)
            except:
                pass

            if not emails_accounts:
                return 0, []  # Email not linked to any GitHub account

            # Extract the resolved username
            username = [*emails_accounts.values()][0]["username"]
            results.append(
                {
                    "label": "Email Resolved",
                    "value": f"{target} → @{username}",
                    "source": PARENT,
                    "group": "📧 Email",
                    "risk": "high",
                }
            )

        # 3. Basic Profile Fetch
        data = await runner.api.query(f"/users/{username}")
        if data.get("message") == "Not Found":
            return 0, []

        runner.target._scrape(data)

        # --- Output Profile Data ---
        grp_gh = "👤 GitHub"
        results.append(
            {
                "label": "Username",
                "value": runner.target.username,
                "source": PARENT,
                "group": grp_gh,
            }
        )
        results.append(
            {
                "label": "ID",
                "value": str(runner.target.id),
                "source": PARENT,
                "group": grp_gh,
            }
        )

        if runner.target.name:
            results.append(
                {
                    "label": "Name",
                    "value": runner.target.name,
                    "source": PARENT,
                    "group": grp_gh,
                }
            )
        if runner.target.company:
            results.append(
                {
                    "label": "Company",
                    "value": runner.target.company,
                    "source": PARENT,
                    "group": grp_gh,
                }
            )
        if runner.target.location:
            results.append(
                {
                    "label": "Location",
                    "value": runner.target.location,
                    "source": PARENT,
                    "group": grp_gh,
                }
            )
        if runner.target.bio:
            results.append(
                {
                    "label": "Bio",
                    "value": runner.target.bio[:100],
                    "source": PARENT,
                    "group": grp_gh,
                }
            )

        # Check for Public Email — API returns it in data["email"], _scrape doesn't set it
        public_email = data.get("email")
        if public_email:
            results.append(
                {
                    "label": "Public Email",
                    "value": public_email,
                    "source": PARENT,
                    "group": "📧 Email",
                    "risk": "high",
                }
            )
            runner.target.emails.add(public_email)

        # --- 3. Domain Recon ---
        if runner.target.company:
            out = guess_custom_domain(runner)
            for company_domain in out:
                domains = set(detect_custom_domain(company_domain))
                for domain in domains:
                    runner.target.domains.add(company_domain)

        if runner.target.blog:
            domains = set(detect_custom_domain(runner.target.blog))
            for domain in domains:
                runner.target.domains.add(domain)

        # --- 4. Active Email Hunt ---

        emails = emails_gen.generate(
            runner,
            default_domains_list=gitfive_config.emails_default_domains,
            domain_prefixes=gitfive_config.email_common_domains_prefixes,
        )

        if emails:
            # metamon.start creates the repo and returns the name
            temp_repo_name, emails_index = await metamon.start(runner, emails)

            if emails_index:
                emails_accounts = await _scrape_commits(
                    runner, temp_repo_name, emails_index
                )

                # Mark is_target now that we know the target username
                for edata in emails_accounts.values():
                    edata["is_target"] = (
                        edata["username"].lower() == runner.target.username.lower()
                    )

                grp_email = "📧 Email (Unmasked)"
                found_private = False

                for email, email_data in emails_accounts.items():
                    if email_data.get("is_target"):
                        results.append(
                            {
                                "label": "Private Email",
                                "value": email,
                                "source": "GitFive Hunt",
                                "group": grp_email,
                                "risk": "critical",
                            }
                        )
                        found_private = True

                if not found_private and not runner.target.emails:
                    results.append(
                        {
                            "label": "Hunt Status",
                            "value": "No private email resolved",
                            "source": PARENT,
                            "group": grp_email,
                        }
                    )

    except Exception as e:
        return 1, [
            {"label": "Error", "value": str(e), "source": PARENT, "risk": "high"}
        ]

    finally:
        # Restore original print function
        builtins.print = original_print

        # 5. Cleanup
        # Since temp_repo_name is now defined outside the try block, this check is safe
        if temp_repo_name:
            try:
                await github.delete_repo(runner, temp_repo_name)
            except:
                pass
        try:
            delete_tmp_dir()
        except:
            pass

    return 0, results
