import os, time, argparse, logging
import yaml
import boto3
import certstream
import tldextract
import requests
from requests.adapters import HTTPAdapter
from queue import Queue
from threading import Thread

S3_URL = "http://s3-1-w.amazonaws.com"
BUCKET_HOST = "%s.s3.amazonaws.com"
QUEUE_SIZE = 100
CHECKED_BUCKETS = list()
FOUND_COUNT = 0
KEYWORDS = [line.strip() for line in open('keywords.txt')]
BUCKET_QUEUE = Queue(maxsize=QUEUE_SIZE)
ARGS = argparse.Namespace()
CONFIG = yaml.safe_load(open('config.yaml'))
S3_CLIENT = boto3.client('s3', aws_access_key_id=CONFIG['aws_access_key'], aws_secret_access_key=CONFIG['aws_secret'])


class BucketWorker(Thread):
    def __init__(self, q, *args, **kwargs):
        self.q = q
        self.session = requests.Session()
        self.session.mount("http://", HTTPAdapter(pool_connections=ARGS.threads, pool_maxsize=QUEUE_SIZE, max_retries=0))

        super().__init__(*args, **kwargs)

    def run(self):
        while True:
            try:
                bucket_url = self.q.get()
                check_response = self.session.head(S3_URL, timeout=3, headers={"Host": bucket_url})

                if check_response.status_code == 307:  # valid bucket, lets check if its public
                    new_bucket_url = check_response.headers["Location"]
                    bucket_response = requests.request('GET' if ARGS.only_interesting else 'HEAD', new_bucket_url, timeout=3)

                    if not ARGS.only_interesting or (ARGS.only_interesting and any(keyword in bucket_response.text for keyword in KEYWORDS)):
                        bucket_name = bucket_url.replace(".s3.amazonaws.com", "")

                        if bucket_response.status_code == 200:
                            bucket_owner = self.get_bucket_owner(bucket_name)
                            print("%s is public%s" % (new_bucket_url, ", owned by " + bucket_owner if bucket_owner else ""))
                            self.log(new_bucket_url)
                        elif bucket_response.status_code == 403 and (CONFIG['aws_access_key'] and CONFIG['aws_secret']):
                            if self.can_access_bucket(bucket_name):
                                bucket_owner = self.get_bucket_owner(bucket_name)
                                print("%s is authenticated%s" % (new_bucket_url, ", owned by " + bucket_owner if bucket_owner else ""))
                                self.log(new_bucket_url)
            except:
                pass
            finally:
                self.q.task_done()

    def log(self, new_bucket_url):
        global FOUND_COUNT
        FOUND_COUNT += 1

        if ARGS.log_to_file:
            with open("buckets.log", "a+") as log:
                log.write("%s%s" % (new_bucket_url, os.linesep))

    def get_bucket_owner(self, bucket_name):
        try:
            result = S3_CLIENT.get_bucket_acl(Bucket=bucket_name)
            return result['Owner']['DisplayName']
        except:
            return None

    def can_access_bucket(self, bucket_name):
        try:
            S3_CLIENT.list_objects(Bucket=bucket_name)
            return True
        except:
            return False

def listen(message, context):
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
                        BUCKET_QUEUE.put(bucket_url)

    if len(CHECKED_BUCKETS) % 100 == 0:
        print("%s buckets checked. %s buckets found" % (len(CHECKED_BUCKETS), FOUND_COUNT))


def get_permutations(parsed_domain):
    perms = [
        "%s" % parsed_domain.domain,
        "www-%s" % parsed_domain.domain,
        "%s-www" % parsed_domain.domain,
        "%s-%s" % (parsed_domain.subdomain, parsed_domain.domain) if parsed_domain.subdomain else "",
        "%s-%s" % (parsed_domain.domain, parsed_domain.subdomain) if parsed_domain.subdomain else "",
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
                        help="Number of threads to spawn. More threads = more power.")
    parser.add_argument("-l", "--log", dest="log_to_file", default=False, action="store_true",
                        help="Log found buckets to a file buckets.log")

    parser.parse_args(namespace=ARGS)
    logging.disable(logging.WARNING)

    if not CONFIG['aws_access_key'] or not CONFIG['aws_secret']:
        print("Enter AWS keys in config.yaml to find even more buckets!")

    for _ in range(1, ARGS.threads):
        BucketWorker(BUCKET_QUEUE).start()

    print("Waiting for certstream events - this could take a few minutes to queue up...")
    certstream.listen_for_events(listen) #blocking

    print("Qutting - waiting for threads to finish up...")
    BUCKET_QUEUE.join()


if __name__ == "__main__":
    main()
