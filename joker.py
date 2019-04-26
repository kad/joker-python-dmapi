#!/usr/bin/env python3
#
# joker.com DMAPI for python
#
# (c) 2019 Alexander D. Kanevskiy <kad@blackcatlinux.com>
#
# SPDX-License-Identifier: Apache-2.0

import os
import re
import sys
from pprint import pprint
import requests


class Joker:
    def __init__(self, api_key="", username="", password="", url="https://dmapi.joker.com"):
        if not api_key and not (username and password):
            raise ValueError("api_key or username/password must be defined")
        self.api_key = api_key
        self.username = username
        self.password = password
        self.url = url
        self.auth_sid = ""
        self.supported_domains = []
        self.account_info = {}

        self.__session = None
        self.__new_session()

    def login(self):
        if self.api_key:
            params = {"api-key": self.api_key}
        elif self.username and self.password:
            params = {"username": self.username, "password": self.password}
        else:
            raise IOError("Can't login: missing credentials")
        response = JokerResponse(self.get_request("login", params))
        code, text = response.status()
        if code != 0:
            raise IOError(text)
        if "Auth-Sid" in response.headers:
            self.auth_sid = response.headers["Auth-Sid"]
        else:
            raise IOError("Unexpected login falure: no Auth-Sid in response")
        self.__update_account_info(response.headers)
        self.supported_domains = response.as_list()
        return response

    def logout(self):
        res = ""
        if self.auth_sid:
            res = self.get_request("logout")
            self.auth_sid = ""
            self.account_info = {}
            self.supported_domains = []
        return JokerResponse(res)

    def dns_zone_list(self, pattern=""):
        params = {}
        if pattern:
            params["pattern"] = pattern
        response = JokerResponse(self.get_request("dns-zone-list", params))
        return response

    def dns_zone_get(self, domain):
        if not domain:
            raise IOError("Domain must be specified")
        response = JokerResponse(self.get_request("dns-zone-get", {"domain": domain}))
        return response

    def dns_zone_put(self, domain, zone):
        if not domain or not zone:
            raise IOError("Domain and zone must not be empty")
        response = JokerResponse(
            self.post_request("dns-zone-put", {"domain": domain, "zone": zone})
        )
        return response

    def get_request(self, command, parameters={}):
        url = self.url + "/request/" + command
        if self.auth_sid:
            parameters["auth-sid"] = self.auth_sid
        self.__new_session()
        try:
            response = self.__session.get(url, params=parameters)
            # pylint: disable=E1101
            if response.status_code != requests.codes.ok:
                raise IOError("HTTP Status Code: %s" % response.status_code)
            return response.text
        except requests.ConnectionError as e:
            raise IOError("Connection Error: %s" % str(e))
        except requests.HTTPError as e:
            raise IOError("Http Error: %s" % str(e))
        except IOError as e:
            raise e
        except Exception as e:
            raise IOError("Unexpected Error: %s" % str(e))

    def post_request(self, command, parameters={}):
        url = self.url + "/request/" + command
        if self.auth_sid:
            parameters["auth-sid"] = self.auth_sid
        self.__new_session()
        try:
            response = self.__session.post(url, data=parameters)
            # pylint: disable=E1101
            if response.status_code != requests.codes.ok:
                raise IOError(
                    "HTTP-Status-Code: %s\n%s" % (response.status_code, response.text)
                )
            return response.text
        except requests.ConnectionError as e:
            raise IOError("Connection Error: %s" % str(e))
        except requests.HTTPError as e:
            raise IOError("Http Error: %s" % str(e))
        except IOError as e:
            raise e
        except Exception as e:
            raise IOError("Unexpected Error: %s" % str(e))

    def __new_session(self):
        if self.__session:
            return
        _needed_headers = {
            "User-Agent": "Joker python DMAPI",
            "Referer": "dmapi.joker.com",
            # "Accept": "application/json, text/javascript, */*; q=0.01",
        }
        session = requests.Session()
        session.headers.update(_needed_headers)
        self.__session = session

    def __update_account_info(self, headers):
        important_headers = [
            "Account-balance",
            "Account-contract_date",
            "Account-currency",
            "Account-rebate",
            "UID",
            "User-Access",
            "User-Login",
        ]
        for key in important_headers:
            if key in headers:
                self.account_info[key] = headers[key]

    def find_domain_for_fdqn(self, fdqn):
        domain = ""
        local_entry = ""
        rzl = self.dns_zone_list()
        if rzl.status()[0] == 0:
            for dom, _ in rzl.as_separated_lists():
                if fdqn.endswith(dom + ".") and len(dom) > len(domain):
                    domain = dom
            # print("Found domain: '%s'" % domain)
        # else:
        # print("Unable to list zones: %s" % rzl.status)
        if domain:
            if fdqn == domain + ".":
                local_entry = "@"
            else:
                local_entry = fdqn[: -len("." + domain + ".")]
        return domain, local_entry

    def add_txt_record(self, domain, record, value, ttl=60):
        if not domain or not record or not value:
            raise ValueError("domain, record or value can't be empty")
        rzg = self.dns_zone_get(domain)
        if rzg.status()[0] != 0:
            return rzg
        zl = rzg.body.splitlines()
        zl.append(
            '%(record)s TXT 0 "%(value)s" %(ttl)d'
            % {"record": record, "value": value, "ttl": ttl}
        )
        zone = "\n".join(zl)
        return self.dns_zone_put(domain, zone)

    def remove_txt_record(self, domain, record, value=""):
        if not domain or not record:
            raise ValueError("domain and record can't be empty")
        rzg = self.dns_zone_get(domain)
        if rzg.status()[0] != 0:
            return rzg
        zl = rzg.body.splitlines()
        old_zone = "\n".join(zl)
        if value:
            # TODO: Some records have additional spaces in the end of values.
            line = '%(record)s TXT 0 "%(value)s"' % {"record": record, "value": value}
        else:
            line = "%(record)s TXT 0 " % {"record": record}
        zl = [l for l in zl if not l.startswith(line)]
        zone = "\n".join(zl)
        if old_zone == zone:
            # print("No changes in the zone: no update necessary")
            return JokerResponse('Status-Code: 0\nStatus-Text: "No update needed"\n')
        return self.dns_zone_put(domain, zone)


class JokerResponse:
    def __init__(self, message):
        self.headers = {}
        self.body = ""
        parts = message.split("\n\n")
        if parts:
            self.headers = JokerResponse.__parse_key_values(parts[0])
        if len(parts) > 1:
            self.body = parts[1]

    def status(self):
        code = -1
        text = ""
        if "Status-Code" in self.headers:
            code = int(self.headers["Status-Code"])
        if "Status-Text" in self.headers:
            text = self.headers["Status-Text"]
        return code, text

    def as_list(self):
        return self.body.splitlines()

    def as_separated_lists(self):
        res = []
        if "Separator" in self.headers and self.headers["Separator"] == "TAB":
            sep = "\t"
        else:
            sep = " "
        for line in self.body.splitlines():
            res.append(line.split(sep))
        return res

    def as_list_of_dicts(self):
        res = []
        if "Columns" in self.headers:
            columns = self.headers["Columns"].split(",")
            for line in self.as_separated_lists():
                entry = {}
                for idx, val in enumerate(line):
                    entry[columns[idx]] = val
                res.append(entry)
        return res

    @staticmethod
    def __parse_key_values(message):
        headers = {}
        for line in message.splitlines():
            split = re.split(r"\s*:\s*", line, 1)
            if len(split) > 1:
                headers[split[0]] = split[1]
            else:
                headers[split[0]] = ""
        return headers


def usage():
    prg = sys.argv[0]
    usage = """Usage:
    %(prg)s: info
    %(prg)s: present <FQDN> <record>
    %(prg)s: cleanup <FQDN> <record>
    %(prg)s: get-zone <domain>
    %(prg)s: put-zone <domain> <zone-file>

    Invoked with: %(args)s
    """ % {
        "prg": prg,
        "args": sys.argv,
    }
    raise SystemExit(usage)


if __name__ == "__main__":
    debug = False
    err = None

    argc = len(sys.argv)
    if argc < 2:
        usage()

    mode = sys.argv[1]
    if mode not in ("info", "present", "cleanup", "get-zone", "put-zone", "test"):
        raise SystemExit("Invalid mode %s" % mode)

    key = os.getenv("JOKER_API_KEY")
    if not key:
        raise SystemExit("JOKER_API_KEY must be defined")

    if debug:
        print("Logging in")
    dmapi = Joker(api_key=key)
    res = dmapi.login()
    code, text = res.status()
    if code != 0:
        raise SystemExit("Unable to login: %s" % text)

    if mode == "info" and argc == 2:
        print("Account info:")
        pprint(dmapi.account_info)
        rzl = dmapi.dns_zone_list()
        if rzl.status()[0] == 0:
            print("Account domains:")
            for domain, expire in rzl.as_separated_lists():
                print("Domain: %s Expires: %s" % (domain, expire))
    elif mode == "present" and argc == 4:
        entry = sys.argv[2]
        value = sys.argv[3]
        domain, record = dmapi.find_domain_for_fdqn(entry)
        if domain:
            print(
                "Adding record '%s' with value '%s' to domain '%s'"
                % (record, value, domain)
            )
            try:
                resp = dmapi.add_txt_record(domain, record, value)
                code, text = resp.status()
                if code != 0:
                    err = text + "\n" + str(resp.headers)
            except IOError as e:
                err = "Error adding TXT entry:\n" + str(e)
    elif mode == "cleanup" and argc == 4:
        entry = sys.argv[2]
        value = sys.argv[3]
        domain, record = dmapi.find_domain_for_fdqn(entry)
        if domain:
            print(
                "Removing record '%s' with value '%s' to domain '%s'"
                % (record, value, domain)
            )
            try:
                resp = dmapi.remove_txt_record(domain, record)
                code, text = resp.status()
                if code != 0:
                    err = text + "\n" + str(resp.headers)
            except IOError as e:
                err = "Error removing TXT entry:\n" + str(e)
    elif mode == "get-zone" and argc == 3:
        rzg = dmapi.dns_zone_get(sys.argv[2])
        code, text = rzg.status()
        if code == 0:
            print(rzg.body)
        else:
            err = text
    elif mode == "put-zone" and argc == 4:
        zone = ""
        if os.path.exists(sys.argv[3]) and os.path.isfile(sys.argv[3]):
            zone = open(sys.argv[3], "r").read().strip()
        else:
            err = "File %s either doesn't exist or not a regular file" % sys.argv[3]
        if zone:
            try:
                rzg = dmapi.dns_zone_put(sys.argv[2], zone)
                code, text = rzg.status()
                if code == 0:
                    print(rzg.body)
                else:
                    err = text
            except IOError as e:
                err = "Error while submitting zone:\n" + str(e)
        else:
            err = "Zone is empty"
    elif mode == "test":
        pass
    else:
        err = "Something wrong. Mode: '%s' arguments: %d" % (mode, argc)

    if debug:
        print("Logging out")
    rl = dmapi.logout()
    code, text = rl.status()
    if text != "OK":
        raise SystemExit("Unable to logout: %s" % text)

    raise SystemExit(err)
