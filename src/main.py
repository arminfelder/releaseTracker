#!/usr/local/bin/python3
import json
import os
import re
import time
from abc import abstractmethod
import datetime

import prometheus_client
import requests as requests
import sortedcontainers as sortedcontainers
from prometheus_client import start_http_server, CollectorRegistry, write_to_textfile


class Version:
    @abstractmethod
    def __init__(self, version: str):
        pass

    @abstractmethod
    def is_valid(self) -> bool:
        pass

    @abstractmethod
    def __str__(self):
        pass

    @abstractmethod
    def __eq__(self, other):
        pass

    @abstractmethod
    def __lt__(self, other):
        pass

    @abstractmethod
    def __gt__(self, other):
        pass


class VersionCollection:
    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def is_empty(self):
        pass

    @abstractmethod
    def insert(self, version: Version):
        pass

    @abstractmethod
    def get_latest_patch(self, version: Version):
        pass

    @abstractmethod
    def get_latest_release(self):
        pass

    @abstractmethod
    def __contains__(self, key):
        pass

    def __add__(self, other):
        pass

    def __iadd__(self, other):
        pass

    @abstractmethod
    def __iter__(self):
        pass

class SemVer(Version):

    def __init__(self, version: str):
        if self.validate(version):
            parts = version.split(".")
            self.major = int(parts[0])
            self.minor = int(parts[1])
            self.patch = int(parts[2])
            self.__valid = True
        else:
            self.__valid = False

    def is_valid(self):
        return self.__valid

    def validate(self, version: str):

        pattern = re.compile("(^[0-9]+\.[0-9]+\.[0-9]+$)")
        if re.match(pattern, version):
            return True
        else:
            return False

    def __str__(self):
        return "{major}.{minor}.{patch}".format(major=self.major, minor=self.minor, patch=self.patch)

    def __eq__(self, other):
        if self.major == other.major and self.minor == other.minor and self.patch == other.patch:
            return True
        else:
            return False

    def __lt__(self, other):
        if self.major < other.major:
            return True
        elif self.minor < other.minor:
            return True
        elif self.patch < other.patch:
            return True
        else:
            return False

    def __gt__(self, other):
        if self.major > other.major:
            return True
        elif self.minor > other.minor:
            return True
        elif self.patch > other.patch:
            return True
        else:
            return False


class SemVerRevision(Version):

    def __init__(self, version: str):
        if self.validate(version):
            parts = version.split(".")
            self.major = int(parts[0])
            self.minor = int(parts[1])
            self.patch = int(parts[2])
            self.revision = int(parts[3])
            self.__valid = True
        else:
            self.__valid = False

    def is_valid(self):
        return self.__valid

    def validate(self, version: str):

        pattern = re.compile("(^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$)")
        if re.match(pattern, version):
            return True
        else:
            return False

    def __str__(self):
        return "{major}.{minor}.{patch}.{revision}".format(major=self.major, minor=self.minor, patch=self.patch,
                                                           revision=self.revision)

    def __eq__(self, other):
        if self.major == other.major and self.minor == other.minor and self.patch == other.patch and self.revision == other.revision:
            return True
        else:
            return False

    def __lt__(self, other):
        if self.major < other.major:
            return True
        elif self.minor < other.minor:
            return True
        elif self.patch < other.patch:
            return True
        elif self.revision < other.revision:
            return True
        else:
            return False

    def __gt__(self, other):
        if self.major > other.major:
            return True
        elif self.minor > other.minor:
            return True
        elif self.patch > other.patch:
            return True
        elif self.revision > other.revison:
            return True
        else:
            return False

    def __iter__(self):
        pass

    def __next__(self):
        pass


class SemVerCollecion:
    def __init__(self):
        self.versions = sortedcontainers.SortedDict()
        self.__iter_major = None
        self.__iter_minor = None
        self.__iter_patch = None

    def __contains__(self, item: SemVer):
        if item.major in self.versions:
            if item.minor in self.versions[item.major]:
                if item in self.versions[item.major][item.minor]:
                    return True
        return False

    def __add__(self, other):
        self.versions.update(other.versions)
        return self

    def __iadd__(self, other):
        self.versions.update(other.versions)
        return self

    def is_empty(self):
        if len(self.versions):
            return False
        else:
            return True

    def insert(self, version: SemVer):
        if version.major not in self.versions:
            self.versions[version.major] = sortedcontainers.SortedDict()
        if version.minor not in self.versions[version.major]:
            self.versions[version.major][version.minor] = sortedcontainers.SortedList()
        self.versions[version.major][version.minor].add(version)

    def get_latest_patch(self, version: SemVer):
        patches = self.versions[version.major][version.minor]
        latest_patch = patches[len(patches) - 1]

        return latest_patch

    def get_latest_release(self):
        major_keys = self.versions.keys()
        major_key = major_keys[-1]
        minor_keys = self.versions[major_key].keys()
        minor_key = minor_keys[-1]
        patch_items = self.versions[major_key][minor_key]

        latest_release = patch_items[len(patch_items) - 1]

        return latest_release

    def get_first_release(self):
        major_keys = self.versions.keys()
        major_key = major_keys[0]
        minor_keys = self.versions[major_key].keys()
        minor_key = minor_keys[0]
        patch_keys = self.versions[major_key][minor_key]

        first_release = patch_keys[0]

        return first_release
    def __iter__(self):
        return self

    def __next__(self):
        if self.__iter_major is None:
            self.__iter_major = iter(self.versions)
        major = next(self.__iter_major)
        minor_dict = self.versions[major]
        if self.__iter_minor is None:
            self.__iter_minor = iter(minor_dict)
        minor = next(self.__iter_minor)
        patch_list = minor_dict[minor]
        if self.__iter_patch is None:
            self.__iter_patch = iter(patch_list)
        patch = next(self.__iter_patch)
        return patch


class SemVerRevisionCollection:
    def __init__(self):
        self.versions = sortedcontainers.SortedDict()

    def __contains__(self, item: SemVerRevision):
        if item.major in self.versions:
            if item.minor in self.versions[item.major]:
                if item.patch in self.versions[item.major][item.minor]:
                    if item in self.versions[item.major][item.minor][item.patch]:
                        return True
        return False

    def __add__(self, other):
        self.versions.update(other.versions)
        return self

    def __iadd__(self, other):
        self.versions.update(other.versions)
        return self

    def is_empty(self):
        if len(self.versions):
            return False
        else:
            return True
    def insert(self, version: SemVerRevision):
        if version.major not in self.versions:
            self.versions[version.major] = sortedcontainers.SortedDict()
        if version.minor not in self.versions[version.major]:
            self.versions[version.major][version.minor] = sortedcontainers.SortedDict()
        if version.patch not in self.versions[version.major][version.minor]:
            self.versions[version.major][version.minor][version.patch] = sortedcontainers.SortedList()

        self.versions[version.major][version.minor][version.patch].add(version)

    def get_latest_patch(self, version: SemVerRevision):
        patches = self.versions[version.major][version.minor].keys()
        patch = patches[-1]
        revisions = self.versions[version.major][version.minor][patch]
        latest_patch = revisions[len(revisions) - 1]

        return latest_patch

    def get_latest_release(self):
        major_keys = self.versions.keys()
        major_key = major_keys[-1]
        minor_keys = self.versions[major_key].keys()
        minor_key = minor_keys[-1]
        patch_keys = self.versions[major_key][minor_key].keys()
        patch_key = patch_keys[-1]
        revision_items = self.versions[major_key][minor_key][patch_key]

        latest_release = revision_items[len(revision_items) - 1]

        return latest_release

    def get_first_release(self):
        major_keys = self.versions.keys()
        major_key = major_keys[0]
        minor_keys = self.versions[major_key].keys()
        minor_key = minor_keys[0]
        patch_keys = self.versions[major_key][minor_key].keys()
        patch_key = patch_keys[0]
        revision_items = self.versions[major_key][minor_key][patch_key]

        first_release = revision_items[0]

        return first_release

    def __iter__(self):
        return self

    def __next__(self):
        if self.__iter_major is None:
            self.__iter_major = iter(self.versions)
        major = next(self.__iter_major)
        minor_dict = self.versions[major]
        if self.__iter_minor is None:
            self.__iter_minor = iter(minor_dict)
        minor = next(self.__iter_minor)
        patch_dict = minor_dict[minor]
        if self.__iter_patch is None:
            self.__iter_patch = iter(patch_dict)
        patch = next(self.__iter_patch)
        revision_list = patch_dict[patch]
        if self.__iter_patch is None:
            self.__iter_patch = iter(revision_list)

class ReleaseSource:
    @abstractmethod
    def get_release_list(self):
        pass


class Github(ReleaseSource):
    def __init__(self, options, token, version_limit):
        """
        :param options:
        :param version_limit: version to stop scrolling back on
        """
        self.__options = options
        self.__token = token

        self.__clean_tag_pattern = None
        if "tagRegEx" in self.__options:
            self.__clean_tag_pattern = re.compile(self.__options["tagRegEx"])

        self.version_type = Version
        self.version_collection_type = VersionCollection
        versioning = self.__options["versioningSchema"]

        if versioning == "semVer":
            self.version_collection_type = SemVerCollecion
            self.version_type = SemVer
        elif versioning == "semVerRevision":
            self.version_collection_type = SemVerRevisionCollection
            self.version_type = SemVerRevision
        else:
            print("error")
        self.__version_limit = self.version_type(str(version_limit))

    def get_releases(self):

        versions = self.version_collection_type()

        url = self.__options["url"]
        page = 1
        while True:
            response = requests.get(url, params={"per_page": 100, "page": page},
                                    headers={"Authorization": "token {}".format(self.__token)})
            data = response.json()
            if len(data):
                release_versions = self.parse_releases_list(data)
                versions += release_versions

                if self.__version_limit in release_versions:
                    break

            else:
                break
            page += 1

        return versions

    def parse_releases_list(self, releases: list):
        versions = self.version_collection_type()
        for release in releases:
            tag = str()
            if "alternativeVersionField" in self.__options:
                tag = release[self.__options["alternativeVersionField"]]
            else:
                tag = release["tag_name"]

            if self.__clean_tag_pattern:
                isolated_version_pattern = re.compile(self.__clean_tag_pattern)
                match_result = re.search(isolated_version_pattern, tag)
                if match_result:
                    tag = match_result.group(1)
                else:
                    continue
            version = self.version_type(tag)
            if version.is_valid():
                versions.insert(version)

        return versions


class ReleaseChecker:
    def __init__(self, interval, software_definition_config, credentials):
        self.__interval = int(interval)
        self.__software_config = software_definition_config
        self.__credentials = credentials
        self.__registry = CollectorRegistry()
        self.__info = prometheus_client.Info(name="version",
                                             documentation="release tracker",
                                             labelnames=["installed",
                                                         "instance_info",
                                                         "latest_stable",
                                                         "latest_patch",
                                                         "product",
                                                         "checked_at"],
                                             namespace="release_tracker")

    def __load_software_list(self):
        print("load config")
        with open(self.__software_config, "r") as f:
            self.__software = json.load(f)

    def check_software_list(self):
        for software in self.__software:
            self.check_software_versions(software)
        output = "test_metrics.prom"
        write_to_textfile(output, self.__registry)


    def check_software_versions(self, software: dict):
        source_type = software["type"]

        version_collection_type = VersionCollection
        versioning = software["options"]["versioningSchema"]

        if versioning == "semVer":
            version_collection_type = SemVerCollecion
            version_type = SemVer
        elif versioning == "semVerRevision":
            version_collection_type = SemVerRevisionCollection
            version_type = SemVerRevision
        else:
            print("error")

        versions = version_collection_type()

        for instance in software["instances"]:
            versions.insert(version_type(instance["version"]))

        releases = version_collection_type()
        match source_type:
            case "github":
                github = Github(options=software["options"],
                                token=self.__credentials["github"]["token"],
                                version_limit=versions.get_first_release()
                                )
                releases = github.get_releases()

            case _:
                print("{} not supported".format(type))

        for instance in software["instances"]:
            version = version_type(instance["version"])
            latest_stable = releases.get_latest_release()
            latest_patch = releases.get_latest_patch(version)
            self.__info.labels(str(version),
                               instance["id"],
                               str(latest_stable),
                               str(latest_patch),
                               software["name"],
                               datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
                               )

    def run(self):

        start_http_server(8000)
        while True:
            self.__load_software_list()
            self.check_software_list()
            time.sleep(self.__interval)


if __name__ == '__main__':
    interval = os.getenv("INTERVAL_SECONDS", "3600")
    software_definition_config = os.getenv("SOFTWARE_CONFIG", "/app/software.json")
    credentials = dict()
    credentials["github"] = dict()
    credentials["github"]["token"] = os.getenv("CREDENTIALS_GITHUB_TOKEN")

    release_checker = ReleaseChecker(interval, software_definition_config, credentials)

    release_checker.run()
