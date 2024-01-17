#!/usr/bin/env python3

import sys
import json
import requests
import time
import hashlib
import logging
import collections
import argparse
import jinja2
import tempfile
import copy
import difflib
import validators

# Fetch the full file and compare its checksum every 7 days.
FULL_FETCH_INTERVAL = 7 * 60 * 60 * 24

# Inspired by https://stackoverflow.com/a/14014877
class TransparentHasher:
    def __init__(self, hasher, source):
        self._hasher = hasher
        self._source = source

    def __iter__(self):
        for chunk in self._source:
            self._hasher.update(chunk)
            yield chunk

    def hasher(self):
        return self._hasher

def check_data(mirrors, urls):
    errors = []

    for mirror_base_url, mirror_config in mirrors.items():
        # Check required fields and their types:
        if type(mirror_base_url) != str \
           or "admins" not in mirror_config \
           or type(mirror_config["admins"]) != list \
           or "dead" not in mirror_config \
           or type(mirror_config["dead"]) != bool \
           or "replicates" not in mirror_config \
           or type(mirror_config["replicates"]) != list:
            errors += [
                f"Missing or invalid field in mirror \"{mirror_base_url}\""
            ]

        # Check that each mirror is named by a valid base URL:
        try:
            validators.url(mirror_base_url)
        except validators.ValidationFailure as e:
            errors += [
                f"Mirror base URL \"{mirror_base_url}\" failed to validate: {e}"
            ]

        # Ensure that the "mirrors" field of a mirror refers to another defined
        # mirror:
        for replicate_mirror in mirror_config.get("replicates", []):
            if type(replicate_mirror) != str:
                errors += [
                    f"Replicate entry of \"{mirror_base_url}\" not a string"
                ]
            elif replicate_mirror not in mirrors:
                errors += [
                    f"Mirror \"{mirror_base_url}\" is set to replicate "
                    + f"non-existant mirror \"{replicate_mirror}\""
                ]

        # Require all active mirrors to have an admin user defined:
        if not mirror_config.get("dead", False) and len(mirror_config.get("admins", [])) == 0:
            errors += [
                f"Mirror \"{mirror_base_url}\" does not have at least one "
                + "admin defined."
            ]

    for url, url_record in urls.items():
        # Check required fields and their types:
        #
        # We ignore the "discovered" field, as it's not relied on by this
        # script. It's only maintained to keep track of which revision
        # introduced a given mirror URL.
        if type(url) != str \
           or "checksum" not in url_record \
           or type(url_record["checksum"]) not in [type(None), str] \
           or "ignored" not in url_record \
           or type(url_record["ignored"]) != bool \
           or "last_fetch" not in url_record \
           or type(url_record["last_fetch"]) not in [type(None), int] \
           or "last_head" not in url_record \
           or type(url_record["last_head"]) not in [type(None), int] \
           or "mirror" not in url_record \
           or type(url_record["mirror"]) != str \
           or "size" not in url_record \
           or type(url_record["size"]) not in [type(None), int]:
            errors += [
                f"Missing or invalid field in URL record \"{url}\""
            ]

        # Make sure that every URL has a mirror defined:
        if not url_record.get("mirror", "") in mirrors:
            errors += [
                f"URL record \"{url}\" points to non-existant mirror."
            ]

        # Ensure that the URL is a sub-URL of mirror's base URL:
        if not url.startswith(url_record.get("mirror", "")):
            errors += [
                f"URL \"{url}\" does not have its mirror URL as prefix."
            ]

    return errors

def mirrorcheck(log, mirrors, urls):
    issues = []

    # Compile a set of replicas for each mirror (the mirrors database
    # defines the reverse mapping). This will make it easier to ensure
    # that another mirror is a complete replica of a given mirror.
    mirror_replicas = {}
    for mirror_base_url, mirror_record in mirrors.items():
        for replicates in mirror_record["replicates"]:
            mirror_replicas.setdefault(replicates, []).append(mirror_base_url)

    # Add all not yet defined mirrors of URLs:
    log.debug("Checking for missing URL mirrors")
    missing_added = True
    while missing_added == True:
        missing_added = False
        url_keys = list(urls.keys())
        for url in url_keys:
            record = urls[url]

            # A shortcut function to "template" an issue dictionary and insert it
            # into the issues list:
            def report_issue(t, mirror=None, **kwargs):
                nonlocal issues
                mirror = record["mirror"] if mirror is None else mirror
                issues += [{
                    "type": t,
                    "url": url,
                    "mirror" : {
                        "base_url": mirror,
                        "admins": mirrors[mirror]["admins"],
                    },
                    **kwargs
                }]

            # We don't skip dead mirrors here. In fact, a good reason to
            # add a replica for a mirror may be to recover from a dead
            # mirror with manually recovered files:
            if record["ignored"] == True:
                log.debug(f"URL \"{url}\" is marked as ignored, skipping...")
                continue

            # Ensure that if this mirror is replicated by some other
            # mirror, all URLs exist on that replica as well:
            mirror_relative_url = url.removeprefix(record["mirror"])
            assert url != mirror_relative_url
            for replica_mirror in mirror_replicas.get(record["mirror"], []):
                replica_url = replica_mirror + mirror_relative_url
                if replica_url in urls:
                    log.debug(f"URL {url} replicated as {replica_url}")
                    # This URL is already replicated. As a sanity check we
                    # make sure that the size and checksum attributes
                    # match up:
                    if urls[replica_url]["size"] != record["size"] \
                       or (record["checksum"] is not None and
                           bytes.fromhex(urls[replica_url]["checksum"])
                           != bytes.fromhex(record["checksum"])):
                        log.warning(
                            f"Replica attributes mismatch! replica mirror: "
                            + f"{replica_mirror}, url: {url}, replica_url: "
                            + f"{replica_url}, size: {record['size']}, "
                            + f"replica size: {urls[replica_url]['size']}, "
                            + f"checksum: {record['checksum']}, "
                            + f"replica checksum: {urls[replica_url]['checksum']}"
                        )
                        report_issue(
                            "replica_attributes_mismatch",
                            # Report this issue for the replica mirror,
                            # not the replicated one:
                            mirror=replica_mirror,
                            url=url,
                            replica_url=replica_url,
                            size=record["size"],
                            replica_size=urls[replica_url]["size"],
                            checksum=record["checksum"],
                            replica_checksum=urls[replica_url]["checksum"],
                        )
                else:
                    log.info(
                        f"Inserting replicated URL for {url} on mirror "
                        + f"{replica_mirror}"
                    )
                    urls[replica_url] = {
                        "checksum": record["checksum"],
                        "discovered": record["discovered"] + [{
                            "replica": url,
                        }],
                        "ignored": False,
                        "last_fetch": None,
                        "last_head": None,
                        "mirror": replica_mirror,
                        "size": record["size"],
                    }

                    # This mirror may have yet other replicas. Thus we
                    # iterate over all URLs again:
                    missing_added = True

    # Fetch each URL that has not been marked "ignored", and where the mirror is
    # not marked "dead".
    for url, record in urls.items():
        if record["ignored"] == True:
            log.debug(f"URL \"{url}\" is marked as ignored, skipping...")
            continue
        elif mirrors[record["mirror"]]["dead"] == True:
            log.debug(f"URL \"{url}\"'s mirror is marked as dead, skipping...")
            continue

        # A shortcut function to "template" an issue dictionary and insert it
        # into the issues list:
        def report_issue(t, **kwargs):
            nonlocal issues
            issues += [{
                "type": t,
                "url": url,
                "mirror" : {
                    "base_url": record["mirror"],
                    "admins": mirrors[record["mirror"]]["admins"],
                },
                **kwargs
            }]

        # Every once in a while, we want to fetch the full file to detect things
        # such as silent data corruption. We further do this when the file's
        # checksum it set to None.
        full_fetch = record["size"] is None \
            or record["checksum"] is None \
            or record["last_fetch"] is None \
            or record["last_fetch"] + FULL_FETCH_INTERVAL < int(time.time())

        method = "GET" if full_fetch else "HEAD"
        log.info(f"Testing URL \"{url}\" ({method})...")

        try:
            if full_fetch:
                resp = requests.get(
                    url, timeout=30, allow_redirects=True, stream=True)
            else:
                resp = requests.head(url, timeout=30, allow_redirects=True)

            # Ensure that we got a non-error response
            resp.raise_for_status()

            # Print the full series of redirects:
            for step in (resp.history if resp.history else []):
                log.info(f"  Followed redirect from \"{step.url}\" ({step.status_code})")
            if resp.history:
                log.info(f"  Final URL: \"{resp.url}\": SUCCESS ({resp.status_code})")

        except Exception as request_exception:
            log.warning(f" FAIL: {request_exception}")
            report_issue("request_error", error_message=str(request_exception))
            continue

        # Validate the received response's Content-Length header:
        resp_content_length = list(filter(
            lambda header: header[0].lower() == "content-length",
            resp.headers.items()))

        if record["size"] is not None \
           and len(resp_content_length) > 0 \
           and int(resp_content_length[0][1]) != record["size"]:
            log.warning(
                f"Diverging content-length header: {resp_content_length[0][1]} "
                + f"bytes fetched now vs. {record['size']} bytes on record"
            )
            report_issue(
                "content_length_header_record_mismatch",
                content_length_header=int(resp_content_length[0][1]),
                record_size=record["size"],
            )
            continue

        if not full_fetch:
            # Everything's okay, update the last_head timestamp:
            record["last_head"] = int(time.time())
        else:
            # We're streaming the response, read it into the SHA-256 hasher and
            # validate that the content_length header matches the true file
            # size:
            hash_filter = TransparentHasher(
                hashlib.sha256(),
                resp.iter_content(chunk_size=16 * 1024))

            # This will stream all data and collect the number of bytes:
            bytes_recvd = sum(map(lambda chunk: len(chunk), hash_filter))

            if int(resp_content_length[0][1]) != bytes_recvd:
                log.warning(
                    f"Received {bytes_recvd} bytes, but Content-Length header "
                    + f"specified {resp_content_length[0][1]} bytes (size on "
                    + f"record: {record['size']} bytes)"
                )
                report_issue(
                    "content_length_header_response_mismatch",
                    content_length_header=int(resp_content_length[0][1]),
                    response_size=bytes_recvd,
                )
                continue

            if record["size"] is not None and record["size"] != bytes_recvd:
                raise Exception(
                    f"Received {bytes_recvd}, but size on record is {record['size']}"
                )
            else:
                # This is the initial fetch, update the size:
                record["size"] = bytes_recvd

            fetch_csum = hash_filter.hasher().digest()
            if record["checksum"] is not None:
                record_csum = bytes.fromhex(record["checksum"])
                if record_csum != fetch_csum:
                    logging.warning(
                        "Received file has diverging checksum ("
                        + f"fetched: {fetch_csum.hex()} vs. on record: "
                        + f"{record_csum.hex()})"
                    )
                    report_issue(
                        "checksum_mismatch",
                        response_checksum=fetch_csum.hex(),
                        record_checksum=record_csum.hex(),
                    )
            else:
                # This is the initial fetch, store the checksum:
                record["checksum"] = fetch_csum.hex()

            # Everything's okay, update the last_fetch timestamp:
            record["last_fetch"] = int(time.time())

        # After the above, we should always have a non-null value for all of
        # last_fetch, size, and checksum:
        assert record["last_fetch"] is not None
        assert record["size"] is not None
        assert record["checksum"] is not None

    return issues

def main():
    parser = argparse.ArgumentParser(
        prog = "mirrorcheck")

    # Global options:
    parser.add_argument("-v", "--verbose", action="store_true")

    # Subcommands:
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # check-data subcommand:
    check_data_parser = subparsers.add_parser("check-data")
    check_data_parser.add_argument(
        "-u", "--urls-json", required=True,
        help="URLs database file")
    check_data_parser.add_argument(
        "-m", "--mirrors-json", required=True,
        help="Mirrors database file")

    # check-mirrors subcommand:
    check_mirrors_parser = subparsers.add_parser("check-mirrors")
    check_mirrors_parser.add_argument(
        "-n", "--dry-run", action="store_true",
        help="Dry run, don't update any state")
    check_mirrors_parser.add_argument(
        "--diff", action="store_true",
        help="Print diff of changes to state")
    check_mirrors_parser.add_argument(
        "-u", "--urls-json", required=True,
        help="URLs database file")
    check_mirrors_parser.add_argument(
        "-m", "--mirrors-json", required=True,
        help="Mirrors database file")
    check_mirrors_parser.add_argument(
        "--gh-issue-template",
        help="Path to GitHub issue template (Jinja2)")
    check_mirrors_parser.add_argument(
        "--gh-issue-out",
        help="GitHub issue file to generate from template in case of errors")

    args = parser.parse_args()

    # Initialize the logging facility:
    ch = logging.StreamHandler()
    fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(fmt)
    log = logging.getLogger('mirrorcheck')
    log.addHandler(ch)
    if args.verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    if args.subcommand in ["check-data", "check-mirrors"]:
        with open(args.urls_json, "r") as f:
            urls = json.load(f)

        with open(args.mirrors_json, "r") as f:
            mirrors = json.load(f)

        errors = check_data(mirrors, urls)

        for error in errors:
            log.error(error)

        if len(errors) != 0:
            log.error(
                "Mirror or URL database has errors or inconsistencies, " +
                "please fix them!"
            )
            return 1

    if args.subcommand == "check-data":
        # Already handled above.
        return 0

    elif args.subcommand == "check-mirrors":
        # Argument sanity checks:
        if args.gh_issue_out and not args.gh_issue_template:
            log.error("Cannot generate GitHub issue without template.")
            return 1

        with open(args.gh_issue_template, "r") as f:
            gh_issue_template = jinja2.Template(f.read())

        updated_urls = copy.deepcopy(urls)
        issues = mirrorcheck(log, mirrors, updated_urls)

        # Ensure the the database is still considered valid with the updated
        # URLs, anything else would indicate an error in this script. If that is
        # the case, we print the diff and then exit.
        updated_data_errors = check_data(mirrors, updated_urls)

        if args.diff or len(updated_data_errors) != 0:
            diffstr = lambda s: list(map(lambda l: l + "\n", s.split("\n")))
            original_str = diffstr(
                json.dumps(urls, indent=2, sort_keys=True))
            updated_str = diffstr(
                json.dumps(updated_urls, indent=2, sort_keys=True))
            sys.stdout.writelines(difflib.unified_diff(
                original_str,
                updated_str,
                fromfile='urls.json',
                tofile='updated.json',
            ))

        if len(updated_data_errors) != 0:
            log.critical("The updated URLs database reports errors:")
            for error in updated_data_errors:
                log.error(error)
            return 1

        if not args.dry_run:
            # Write the results back to the urls.json file:
            with open(args.urls_json, "w") as f:
                json.dump(updated_urls, f, indent=2, sort_keys=True)

        if args.gh_issue_out and len(issues) != 0:
            with open(args.gh_issue_out, "w") as f:
                f.write(gh_issue_template.render(issues=issues))

        if len(issues) != 0:
            return 1

    else:
        log.critical(f"Unhandled subcommand: {args.subcommand}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
