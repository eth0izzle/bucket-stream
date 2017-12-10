import os
import time
import signal
import argparse
import logging
import yaml
from boto3.session import Session
from certstream.core import CertStreamClient
import tldextract
import requests
from requests.adapters import HTTPAdapter
from queue import Queue
from threading import Thread
from threading import Lock
from termcolor import cprint

ARGS = argparse.Namespace()
CONFIG = yaml.safe_load(open("config.yaml"))
KEYWORDS = [line.strip() for line in open("keywords.txt")]
S3_URL = "http://s3-1-w.amazonaws.com"
BUCKET_HOST = "%s.s3.amazonaws.com"
QUEUE_SIZE = CONFIG['queue_size']
UPDATE_INTERVAL = CONFIG['update_interval']  # seconds
RATE_LIMIT_SLEEP = CONFIG['rate_limit_sleep']  # seconds

CHECKED_BUCKETS = list()
FOUND_COUNT = 0


class UpdateThread(Thread):
    def __init__(self, q, *args, **kwargs):
        self.q = q

        super().__init__(*args, **kwargs)

    def run(self):
        while True:
            if len(CHECKED_BUCKETS) > 1:
                cprint("%s buckets checked, %s buckets found" %
                       (len(CHECKED_BUCKETS), FOUND_COUNT), "cyan")

            time.sleep(UPDATE_INTERVAL)


class CertStreamThread(Thread):
    def __init__(self, q, *args, **kwargs):
        self.q = q
        self.c = CertStreamClient(
            self.process, skip_heartbeats=True, on_open=None, on_error=None)

        super().__init__(*args, **kwargs)

    def run(self):
        cprint("Waiting for Certstream events - this could take a few minutes to queue up...",
               "yellow", attrs=["bold"])
        self.c.run_forever()

    def process(self, message, context):
        if message["message_type"] == "heartbeat":
            return

        if message["message_type"] == "certificate_update":
            all_domains = message["data"]["leaf_cert"]["all_domains"]

            if ARGS.skip_lets_encrypt and "Let's Encrypt" in message["data"]["chain"][0]["subject"]["aggregated"]:
                return

            for domain in set(all_domains):
                # cut the crap
                if not domain.startswith("*.") and "cloudflaressl" not in domain and "xn--" not in domain and domain.count("-") < 4 and domain.count(".") < 4:
                    for permutation in get_permutations(tldextract.extract(domain)):
                        bucket_url = BUCKET_HOST % permutation

                        if bucket_url not in CHECKED_BUCKETS:
                            CHECKED_BUCKETS.append(bucket_url)
                            self.q.put(bucket_url)


class BucketQueue(Queue):
    def __init__(self, maxsize):
        self.lock = Lock()
        self.rate_limited = False
        self.next_yield = 0

        super().__init__(maxsize)

    def get(self):
        with self.lock:
            t = time.monotonic()
            if self.rate_limited and t < self.next_yield:
                time.sleep(self.next_yield - t)
                t = time.monotonic()
                self.rate_limited = False

            self.next_yield = t + RATE_LIMIT_SLEEP

        return super().get()


class BucketWorker(Thread):
    def __init__(self, q, *args, **kwargs):
        self.q = q
        self.use_aws = CONFIG["aws_access_key"] and CONFIG["aws_secret"]

        if self.use_aws:
            self.session = Session(
                aws_access_key_id=CONFIG["aws_access_key"], aws_secret_access_key=CONFIG["aws_secret"]).resource("s3")
        else:
            self.session = requests.Session()
            self.session.mount(
                "http://", HTTPAdapter(pool_connections=ARGS.threads, pool_maxsize=QUEUE_SIZE, max_retries=0))

        super().__init__(*args, **kwargs)

    def run(self):
        while True:
            try:
                bucket_url = self.q.get()
                self.__check_boto(
                    bucket_url) if self.use_aws else self.__check_http(bucket_url)
            except Exception as e:
                print(e)
                pass
            finally:
                self.q.task_done()

    def __check_http(self, bucket_url):
        check_response = self.session.head(
            S3_URL, timeout=3, headers={"Host": bucket_url})

        if not ARGS.ignore_rate_limiting and (check_response.status_code == 503 and check_response.reason == "Slow Down"):
            self.q.rate_limited = True
            # add it back to the bucket for re-processing
            self.q.put(bucket_url)
        elif check_response.status_code == 307:  # valid bucket, lets check if its public
            new_bucket_url = check_response.headers["Location"]
            bucket_response = requests.request(
                "GET" if ARGS.only_interesting else "HEAD", new_bucket_url, timeout=3)

            if bucket_response.status_code == 200 and (not ARGS.only_interesting or (ARGS.only_interesting and any(keyword in bucket_response.text for keyword in KEYWORDS))):
                cprint("Found bucket '{}'".format(
                    new_bucket_url), "green", attrs=["bold"])
                self.__log(new_bucket_url)

    def __check_boto(self, bucket_url):
        bucket_name = bucket_url.replace(".s3.amazonaws.com", "")

        try:
            # just to check if the bucket exists. Throws NoSuchBucket exception if not
            self.session.meta.client.head_bucket(Bucket=bucket_name)

            if not ARGS.only_interesting or (ARGS.only_interesting and self.__bucket_contains_any_keywords(bucket_name)):
                owner = None
                acls = None

                try:
                    # todo: also check IAM policy as it can override ACLs
                    acl = self.session.meta.client.get_bucket_acl(
                        Bucket=bucket_name)
                    owner = acl["Owner"]["DisplayName"]
                    acls = ". ACLs = {} | {}".format(self.__get_bucket_perms(
                        acl, "AllUsers"), self.__get_bucket_perms(acl, "AuthenticatedUsers"))
                except:
                    acls = ". ACLS = (could not read)"

                color = "green" if not owner else "magenta"
                cprint("Found bucket '{}'. Owned by '{}'{}".format(
                    bucket_url, owner if owner else "(unknown)", acls), color, attrs=["bold"])
                self.__log(bucket_url)
        except:
            pass

    def __get_bucket_perms(self, acl, group):
        group_uri = "http://acs.amazonaws.com/groups/global/%s" % group
        perms = [g["Permission"] for g in acl["Grants"] if g["Grantee"]
                 ["Type"] == "Group" and g["Grantee"]["URI"] == group_uri]

        return "{}: {}".format(group, ", ".join(perms) if perms else "(none)")

    def __bucket_contains_any_keywords(self, bucket_name):
        try:
            objects = [o.key for o in self.session.Bucket(
                bucket_name).objects.all()]
            return any(keyword in ",".join(objects) for keyword in KEYWORDS)
        except:
            return False

    def __log(self, new_bucket_url):
        global FOUND_COUNT
        FOUND_COUNT += 1

        if ARGS.log_to_file:
            with open("buckets.log", "a+") as log:
                log.write("%s%s" % (new_bucket_url, os.linesep))


def get_permutations(parsed_domain):
    perms = [
        "%s" % parsed_domain.domain,
        "www-%s" % parsed_domain.domain,
        "%s-www" % parsed_domain.domain,
        "%s-%s" % (parsed_domain.subdomain,
                   parsed_domain.domain) if parsed_domain.subdomain else "",
        "%s-%s" % (parsed_domain.domain,
                   parsed_domain.subdomain) if parsed_domain.subdomain else "",
        "%s-backup" % parsed_domain.domain,
        "backup-%s" % parsed_domain.domain,
        "%s-dev" % parsed_domain.domain,
        "dev-%s" % parsed_domain.domain,
        "%s-staging" % parsed_domain.domain,
        "staging-%s" % parsed_domain.domain,
        "%s-test" % parsed_domain.domain,
        "test-%s" % parsed_domain.domain,
        "%s-prod" % parsed_domain.domain,
        "prod-%s" % parsed_domain.domain,
        "%s-uat" % parsed_domain.domain,
        "%s-storage" % parsed_domain.domain
    ]

    return filter(None, perms)


def main():
    parser = argparse.ArgumentParser(description="Find interesting Amazon S3 Buckets by watching certificate transparency logs.",
                                     usage="python bucket-stream.py",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--only-interesting", action="store_true", dest="only_interesting", default=False,
                        help="Only log 'interesting' buckets whose contents match anything within keywords.txt")
    parser.add_argument("--skip-lets-encrypt", action="store_true", dest="skip_lets_encrypt", default=False,
                        help="Skip certs (and thus listed domains) issued by Let's Encrypt CA")
    parser.add_argument("-t", "--threads", metavar="", type=int, dest="threads", default=20,
                        help="Number of threads to spawn. More threads = more power. Limited to 5 threads if unauthenticated.")
    parser.add_argument("--ignore-rate-limiting", action="store_true", dest="ignore_rate_limiting", default=False,
                        help="If you ignore rate limits not all buckets will be checked")
    parser.add_argument("-l", "--log", dest="log_to_file", default=False, action="store_true",
                        help="Log found buckets to a file buckets.log")

    parser.parse_args(namespace=ARGS)
    logging.disable(logging.WARNING)

    if not CONFIG["aws_access_key"] or not CONFIG["aws_secret"]:
        cprint("It is highly recommended to enter AWS keys in config.yaml otherwise you will be severely rate limited! You might want to run with --ignore-rate-limiting", "red")

        if ARGS.threads > 5:
            cprint(
                "No AWS keys, reducing threads to 5 to help with rate limiting.", "red")
            ARGS.threads = 5

    threads = list()

    try:
        q = BucketQueue(maxsize=QUEUE_SIZE)
        threads.extend([BucketWorker(q) for _ in range(0, ARGS.threads)])
        threads.extend([UpdateThread(q), CertStreamThread(q)])
        [t.start() for t in threads]

        signal.pause()  # pause the main thread
    except KeyboardInterrupt:
        cprint("Quitting - waiting for threads to finish up...",
               "yellow", attrs=["bold"])
        [t.join() for t in threads]


if __name__ == "__main__":
    main()
